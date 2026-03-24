# **Cisco ASA ACME Certificate Renewer**

This Python script automates the process of obtaining a signed TLS certificate from **Let's Encrypt** (via the ACME protocol) and installing it onto a **Cisco ASA** security appliance. It specifically uses the **DNS-01 challenge** via the **Porkbun API** to validate domain ownership.


## **Features**

- **Automated ACME Workflow**: Handles registration, challenge validation, and certificate issuance.

- **Porkbun DNS Integration**: Automatically creates and updates the required TXT records for DNS-01 validation.

- **Cisco ASA Automation**: Uses Netmiko to check certificate expiry and perform the complex multi-step import of the certificate chain and identity certificate.

- **Smart Renewal**: Only performs a renewal if the current certificate is missing or within 30 days of expiration.

- **Device-Generated CSR**: Requests a CSR directly from the ASA to ensure the private key remains secure on the device.


## **Prerequisites**

### **1. Required Python Libraries**

Install the necessary dependencies using pip:

```
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

### **2. Porkbun API Access**

You must have a domain registered at Porkbun and possess your **API Key** and **Secret Key**.


### **3. ASA Configuration**

The script requires an existing **trustpoint** name on the ASA to target for updates.

```
crypto key generate rsa label acme-auto-trustpoint modulus 4096
crypto ca trustpoint acme-auto-trustpoint
 enrollment terminal
 fqdn your.domain.here
 alt-fqdn additional.domain.here
 subject-name CN=your.domain.here
 keypair acme-auto-trustpoint
 no validation-usage
 crl configure
```

## **Usage**

### **Registering a New Account**

The first time you run the script, you must create an ACME account and save the credentials to a file:

```
python main.py 
	--create-account
	--email "your-email@example.com"
	--porkbun-api "PK..."
	--porkbun-secret "SK..."
	--porkbun-domain "example.com"
	--device-hostname "asa.example.com"
	--device-username "admin"
	--device-password "password"
	--device-trustpoint "acme-auto-trustpoint"
```

Note: This will also perform a certificate installation on the target device as well as register an account.
You should backup the created `.acme_account_data` somewhere safe.

### **Regular Renewal Run**

Once the account file (default: `.acme_account_data`) is created, you can run the script without the --create-account flag:

```
python main.py 
	--porkbun-api "PK..."
	--porkbun-secret "SK..."
	--porkbun-domain "example.com"
	--device-hostname "asa.example.com"
	--device-username "admin"
	--device-password "password"
	--device-trustpoint "acme-auto-trustpoint"
```

### **Key Arguments**

|                     |                                                                |
| ------------------- | -------------------------------------------------------------- |
| **Argument**        | **Description**                                                |
| --directory-uri     | The ACME directory URL (Defaults to Let's Encrypt Production). |
| --account-file      | Path to the JSON file storing ACME account data.               |
| --porkbun-domain    | The root domain managed in your Porkbun account.               |
| --device-hostname   | The FQDN of the ASA (must contain the root domain).            |
| --device-trustpoint | The name of the trustpoint on the ASA to be updated.           |


## **How It Works**

1. **Expiry Check**: Connects to the ASA and parses the output of show crypto ca certificates to determine if renewal is necessary.

2. **CSR Acquisition**: Triggers the ASA to generate a new CSR via crypto ca enroll.

3. **DNS-01 Challenge**: Contacts the ACME server, receives a challenge, and uses the Porkbun API to create the temporary TXT record.

4. **Certificate Issuance**: After DNS propagation, the script finalizes the order and retrieves the certificate chain.

5. **Installation**: Logically maps the certificates and pushes them to the ASA, using nointeractive mode to ensure the configuration is applied correctly.