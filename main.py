#!/usr/bin/env python3
import os, base64, random, string, josepy, pickle, argparse, logging, sys, textwrap, pprint, json, time, datetime, porkbun_api
from acme import client, messages, challenges, errors
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
from netmiko import ConnectHandler

USER_AGENT = "python-acme/asa-cert-renewal"
#DEFAULT_DIRECTORY_URI = "https://acme-staging-v02.api.letsencrypt.org/directory"
DEFAULT_DIRECTORY_URI = "https://acme-v02.api.letsencrypt.org/directory"

############# Logging Setup

# Custom logging formatter for console
class CustomFormatter(logging.Formatter):

    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# Generic logging setup
LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

# Console Logging with colours
ch = logging.StreamHandler()
ch.setFormatter(CustomFormatter())
LOGGER.addHandler(ch)

############# ACME Client

class LetsEncrypt:
    def __init__(self, account_file, directory_uri, root_domain):
        self.acme_directory_uri = directory_uri
        self.account_file_path = account_file
        self.root_domain = root_domain
        self.account_user_key = None
        self.account_data = None

    def create_account(self, email_address):
        # Check if we are about to overwrite an existing account and error
        if os.path.isfile(self.account_file_path):
            LOGGER.error("Account data already exists at file %s, refusing to create a new account", self.account_file_path)
            LOGGER.error("To create a new account anyway, remove this file manually and retry, or set another account file path with --account-file")
            return None

        # Create a new user private/public key combination
        new_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        try:
            # Fetch the directory and init the ACME client
            LOGGER.debug("Contacting directory server at '%s'", self.acme_directory_uri)
            net = client.ClientNetwork(josepy.JWKRSA(key=new_private_key), user_agent=USER_AGENT)
            directory = messages.Directory.from_json(net.get(self.acme_directory_uri).json())
            client_acme = client.ClientV2(directory, net=net)

            # Register account with ACME directory
            LOGGER.debug("Registering with directory using email address '%s'", email_address)
            client_registration_response = client_acme.new_account(messages.NewRegistration.from_data(email=email_address, terms_of_service_agreed=True))
            client_formatted_private_key = new_private_key.private_bytes(
                encoding=serialization.Encoding.PEM, 
                format=serialization.PrivateFormat.PKCS8,  
                encryption_algorithm=serialization.NoEncryption()
            )

        except Exception as Ex:
            LOGGER.error("Registration failed, exception %s", Ex)
            return None

        # Check response status
        if client_registration_response.body is None or client_registration_response.body.status != "valid":
            LOGGER.error("Registration failed, status response is not 'valid' (%s)", client_registration_response.status)
            return None

        # Format the account data
        pkey_data = { 
            "private_key": client_formatted_private_key.decode(),
            "account_data": client_registration_response.to_json(),
            "directory": self.acme_directory_uri
        }

        try:
            with open(self.account_file_path, "w") as file:
                LOGGER.debug("Writing account data to '%s'", self.account_file_path)
                json.dump(pkey_data, file)

        except Exception as Ex:
            LOGGER.error("Failed to write account data to file %s, exception %s", self.account_file_path, Ex)
            return None

        # Return new account data
        return pkey_data

    def load_account_file(self):
        try:
            with open(self.account_file_path, "r") as file:
                # Load data from the JSON file
                LOGGER.debug("Reading account data from '%s'", self.account_file_path)
                account_data = json.load(file)

                # Parse the private key
                self.account_user_key = josepy.JWKRSA(key=serialization.load_pem_private_key(
                    account_data["private_key"].encode(),
                    password=None
                ))

                self.account_data = messages.RegistrationResource.from_json(account_data["account_data"])
                self.acme_directory_uri = account_data["directory"]
                return (self.account_user_key != None)

        except Exception as Ex:
            LOGGER.debug("Failed to read account data from file %s, exception %s", self.account_file_path, Ex)
            return False

    def request_certificate(self, certificate_domain=None, key_size=4096, certificate_request=None):
        # Create ACME client
        net = client.ClientNetwork(self.account_user_key, account=self.account_data, user_agent=USER_AGENT)
        directory = messages.Directory.from_json(net.get(self.acme_directory_uri).json())
        client_acme = client.ClientV2(directory, net=net)

        # Create private key
        certificate_pkey_formatted = None
        if certificate_request is None:
            if certificate_domain is None:
                raise ValueError("Certificate domain or CSR must be provided to request_certificate")

            LOGGER.debug("Creating Private Key with modulus %d", key_size)
            certificate_pkey = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
            certificate_pkey_formatted = certificate_pkey.private_bytes(
                encoding=serialization.Encoding.PEM, 
                format=serialization.PrivateFormat.PKCS8,  
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
            LOGGER.debug("Created private key:\n%s", certificate_pkey_formatted)

            # Create certificate request
            LOGGER.debug("Creating CSR for domain %s", certificate_domain)
            certificate_details = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, certificate_domain)
            ])

            certificate_request_new = x509.CertificateSigningRequestBuilder().subject_name(certificate_details)
            certificate_request_new.add_extension(x509.SubjectAlternativeName([
                x509.DNSName(certificate_domain)
            ]), critical=False)

            # Sign the certificate request with our private key
            certificate_request = (certificate_request_new.sign(certificate_pkey, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)).decode()
            LOGGER.debug("Created CSR:\n%s", certificate_request)

        # Send CSR to ACME server and receive the challenge requests
        try:
            certificate_order = client_acme.new_order(certificate_request.encode('ASCII'))

        except Exception as Ex:
            LOGGER.error("Failed to request certificate challenges from ACME server, exception %s", Ex)
            return False

        # Iterate over the challenge requests
        needs_wait = False
        accepted_challenges = []
        for requests in certificate_order.authorizations:
            domain_request = requests.body.identifier.value
            for challenge in requests.body.challenges:
                if not isinstance(challenge.chall, challenges.DNS01):
                    continue

                # Obtain the challenge
                response, validation = challenge.response_and_validation(client_acme.net.key)
                validation_domain = challenge.chall.validation_domain_name(domain_request)
                LOGGER.debug("Found DNS01 challenge %s (%s)", validation, challenge.status)

                # Create the DNS entry (if needed)
                if challenge.status is messages.STATUS_PENDING:
                    needs_wait = True
                    LOGGER.info("Processing pending challenge, updating DNS entry %s => %s", validation_domain, validation)
                    if self.create_dns_entry(validation_domain, validation) is False:
                        return

                # Complete the challenge
                accepted_challenges.append((challenge, response))
                break

        # Initial wait period for DNS propagation
        if needs_wait:
            LOGGER.debug("Waiting 60 seconds for DNS propagation")
            time.sleep(60)

        # Finalise order and obtain certificate
        completed_attempts = 2
        while True:
            try:
                LOGGER.info("Requesting certificate from ACME server")
                for (challenge, response) in accepted_challenges:
                    client_acme.answer_challenge(challenge, response)
                certificate_order_finalised = client_acme.poll_and_finalize(certificate_order)
                if certificate_order_finalised.body.status is messages.STATUS_VALID:
                    LOGGER.info("Certificate issued by ACME server for domain %s", certificate_domain)
                    break

                else:
                    LOGGER.error("Certificate was not issued for some reason due to being invalid. Please inspect payload")
                    pprint.pprint(certificate_order_finalised.body)
                    return False

            except errors.ValidationError as Ex:
                LOGGER.debug("DNS validation error: %s", Ex)
                if completed_attempts > 10:
                    LOGGER.error("Failed DNS validation. 10 attempts exceeded with no STATUS_VALID message from ACME server")
                    LOGGER.error("Error: %s", Ex)
                    return False

                else:
                    LOGGER.info("Waiting 120 seconds for DNS validation. (Attempt %d/10)", completed_attempts)
                    completed_attempts += 1
                    time.sleep(120)

        # Output certificate
        LOGGER.debug("Retrieved certificate:\n%s", certificate_order_finalised.fullchain_pem)
        return certificate_order_finalised.fullchain_pem, certificate_pkey_formatted

    def create_dns_entry(self, recordname, recordvalue):
        try:
            record_exists = porkbun_api.read(domain=self.root_domain, subdomain=recordname.replace(f".{self.root_domain}", ""), rtype="TXT")
            if len(record_exists) > 0:
                porkbun_api.update(domain=self.root_domain, subdomain=recordname.replace(f".{self.root_domain}", ""), rtype="TXT", content=recordvalue, ttl=60)
            else:
                porkbun_api.create(domain=self.root_domain, subdomain=recordname.replace(f".{self.root_domain}", ""), rtype="TXT", content=recordvalue, ttl=60)

        except Exception as Ex:
            LOGGER.error("Failed to create domain entry in porkbun for domain %s, name %s (%s)", self.root_domain, recordname, Ex)
            return False

############# ASA Certificate Installation

class ASACertInstaller:
    def __init__(self, device_hostname, device_username, device_password, device_trustpoint):
        self.device_trustpoint = device_trustpoint
        self.connect_handler = ConnectHandler(**{
            "device_type": "cisco_asa",
            "host": device_hostname,
            "username": device_username,
            "password": device_password
        })

    def check_renewal_needed(self):
        output_data = self.connect_handler.send_command(f"show crypto ca certificates {self.device_trustpoint} | include date:")
        if output_data == "":
            LOGGER.info("Trustpoint not found or no certificate attached, attempting renewal anyway..")
            return True

        # At least in all my tests the ASA returns the actual cert first and then anything else in the chain
        # So we will pull the first two lines. There is probably a more elegant/reliable way to do this but
        # the on device filtering is limited on the ASA
        # Date format: 09:27:28 UTC Dec 2 2025
        # Python     : %H:%M:%S %Z  %b  %d %Y
        date_data = {}
        split_data = output_data.split('\n')
        cert_end_date = datetime.datetime.strptime((split_data[1].split('date:')[1]).strip(), "%H:%M:%S %Z %b %d %Y")
        cert_start_date = datetime.datetime.strptime((split_data[0].split('date:')[1]).strip(), "%H:%M:%S %Z %b %d %Y")
        LOGGER.debug("Retrieved trustpoint %s validity; Start: %s, End: %s", self.device_trustpoint, cert_start_date, cert_end_date)

        # Check expiry date
        expiry_offset = cert_end_date - datetime.datetime.now()
        if expiry_offset.days <= 0:
            LOGGER.warning("Certificate at trustpoint %s expired %d days ago!", self.device_trustpoint, expiry_offset.days*-1)
        elif expiry_offset.days < 30:
            LOGGER.info("Certificate at trustpoint %s expires in %d days, which is within the 30 day renewal window", self.device_trustpoint, expiry_offset.days)
        else:
            return False
        return True

    def install_certificate(self, cert, csr):
        # Load the CSR
        certificate_request = x509.load_pem_x509_csr(csr.encode('ASCII'))

        # Load certificate chain
        cert_chain = []
        issued_certificate = None
        for certificate in cert.split("\n\n"):
            # Load certificate
            this_cert = x509.load_pem_x509_certificate(certificate.encode('ASCII'))
            LOGGER.debug("Loaded certificate subject %s from cert chain", this_cert.subject)

            # Check if this is our device certificate
            if this_cert.public_key() == certificate_request.public_key():
                LOGGER.info("Found certificate matching our CSR with subject %s", this_cert.subject)
                issued_certificate = certificate
            else:
                cert_chain.append(certificate)

        # Create the configuration command set.
        # "nointeractive" on ASA means we keep config prompt which makes netmiko happy, though technically its an ASDM only option
        # Note we also remove the trustpoint, as the ASA is to dumb to allow you to replace the trustpoint with a new one without
        # removing everything first. (*grumpy noises*)
        full_command_set = [f"crypto ca import {self.device_trustpoint} certificate nointeractive"]
        full_command_set += issued_certificate.split('\n')
        full_command_set.append("quit")
        full_command_set.append(f"crypto ca authenticate {self.device_trustpoint} nointeractive")
        full_command_set += cert_chain[0].split('\n')
        full_command_set.append("quit")

        # Issue commands to device
        LOGGER.debug("Executing command set:\n%s", '\n'.join(full_command_set))
        output = self.connect_handler.send_config_set(full_command_set)
        output += self.connect_handler.save_config()

        # Validation output
        if "Certificate successfully imported" in output:
            validation_data = self.connect_handler.send_command(f"show crypto ca certificates {self.device_trustpoint}")
            LOGGER.info("CA Certificate and Signed Certificate installed to trustpoint %s\n%s", self.device_trustpoint, validation_data)
            return True

        LOGGER.warning("Certificate may not have been installed, review trustpoint on device and logs:\n%s", output)
        return False

    def get_device_csr(self):
        # Request a new CSR from the device to renew against
        command_set = [f"crypto ca enroll {self.device_trustpoint} noconfirm"]
        output = self.connect_handler.send_config_set(command_set)

        # Parse the CSR into text
        LOGGER.debug("Requesting CSR from device")
        csr_data = None
        for line in output.split('\n'):
            if "CERTIFICATE REQUEST" in line and csr_data is not None:
                csr_data += f"{line}\n"
                break
            elif "CERTIFICATE REQUEST" in line and csr_data is None:
                csr_data = f"{line}\n"
            elif csr_data is not None:
                csr_data += f"{line}\n"

        # Return to request path
        LOGGER.debug("Retrieved CSR:\n%s", csr_data)
        return csr_data

############# Main code flow

def main(argv=None):
    # Setup argument parser
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script automates the process of getting a signed TLS certificate from Let's Encrypt using the ACME protocol.
            It will then install it onto a Cisco ASAv as per the command line arguments
        """)
    )
    # Optional arguments
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
    parser.add_argument("--directory-uri", default=DEFAULT_DIRECTORY_URI, help="certificate authority directory url, default is Let's Encrypt")
    parser.add_argument("--email", default=None, help="Contact details (e.g. mailto:aaa@bbb.com) for your account-key. Required if --create-account is set")
    parser.add_argument("--create-account", action=argparse.BooleanOptionalAction, default=False, help="Create a new account with the ACME server and save it to --account-file")
    parser.add_argument("--account-file", default=".acme_account_data", help="File to read/save account data for the ACME server to")
    # API arguments for DNS updates
    parser.add_argument("--porkbun-api", required=True, help="API ID for the Porkbun API")
    parser.add_argument("--porkbun-secret", required=True, help="API Secret for the Porkbun API")
    parser.add_argument("--porkbun-domain", required=True, help="The domain name to target in the Porkbun API")
    # Arguments for certificate
    parser.add_argument("--device-hostname", required=True, help="FQDN of the device to update the certificate on. Used for connecting to the device and the hostname for the certificate")
    parser.add_argument("--device-username", required=True, help="Username to connect to the device with")
    parser.add_argument("--device-password", required=True, help="Password to connect to the device with")
    parser.add_argument("--device-trustpoint", required=True, help="The name of the trustpoint to update with the new certificate")
    args = parser.parse_args(argv)
    pprint.pprint(args)

    # Reconfigure logging if it has been changed from the arguments
    LOGGER.setLevel(args.quiet or LOGGER.level)

    # Setup Porkbun API
    porkbun_api.APIKEY = args.porkbun_api
    porkbun_api.SECRETAPIKEY = args.porkbun_secret

    # Create ACME class and create account if requested
    acme_class = LetsEncrypt(account_file=args.account_file, directory_uri=args.directory_uri, root_domain=args.porkbun_domain)
    if args.create_account is True:
        if args.email is None or "@" not in args.email:
            LOGGER.error("--create-account requires --email is set to a valid email address.")
            exit()

        new_account_data = acme_class.create_account(args.email)
        if new_account_data is None:
            exit()

        LOGGER.info("Account registered successfully")

    # Check that we have a valid account before continuing
    if not acme_class.load_account_file():
        LOGGER.error("Unable to load the account information from the file %s", args.account_file)
        LOGGER.error("Please validate the file path or --account-file argument, or create a new account with --create-account=true")
        exit()

    # Validate the porkbun domain exists in the hostname we are requesting
    if args.porkbun_domain not in args.device_hostname:
        LOGGER.error("The hostname of the device %s must contain the root domain %s!!!", args.device_hostname, args.porkbun_domain)
        exit()

    # Create the connection to the device
    device_class = ASACertInstaller(device_hostname=args.device_hostname, device_username=args.device_username, device_password=args.device_password, device_trustpoint=args.device_trustpoint)
    if not device_class.check_renewal_needed():
        LOGGER.info("The trustpoint on the device %s is not yet due for renewal", args.device_hostname)
        exit()

    # Retrieve CSR
    device_csr = device_class.get_device_csr()
    if device_csr is None:
        LOGGER.error("Device trustpoint configuration is invalid, no CSR was returned. Fix the device config")
        exit()

    # Renew certificate
    cert, private_key = acme_class.request_certificate(args.device_hostname, certificate_request=device_csr)
    device_class.install_certificate(cert, device_csr)

if __name__ == "__main__":
    main(sys.argv[1:])
