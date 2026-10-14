# Burp Suite mTLS PKCS#12 Client Certificate Generator

A small Python utility that converts a client certificate and matching private key into a PKCS#12 (`.p12`) file that Burp Suite can use for mutual TLS (mTLS) client authentication.

This script validates the certificate and key, checks that they belong together, supports PEM and DER inputs, handles encrypted private keys, and exports a Burp-compatible client certificate bundle.

## What it does

- Validates the client certificate and private key
- Detects PEM or DER certificate/key formats
- Prompts for the private key password if the key is encrypted
- Confirms the certificate and private key match by comparing their public key hashes
- Checks certificate validity dates and Extended Key Usage (EKU)
- Optionally includes intermediate certificates from the certificate chain
- Exports a PKCS#12 file with a password you choose
- Verifies the generated `.p12` file with OpenSSL

## Requirements

- Python 3.9+
- OpenSSL installed and available in `PATH`

On Linux/macOS:

```bash
openssl version
```

If `openssl` is not found, install it and ensure it is in your system `PATH`.

## Usage

Run the script:

```bash
python burp_client_p12_generator.py
```

The script will ask for:

1. Client certificate file path
2. Private key file path
3. New password for the generated `.p12` file
4. Existing private key password (if the key is encrypted)
5. Output path for the final PKCS#12 file

Example flow:

```text
Enter CLIENT CERTIFICATE path: /path/to/client.crt
Enter PRIVATE KEY path: /path/to/client.key
Enter NEW password for generated .p12 file: MyStrongPassword!
```

If the key is encrypted:

```text
[!] Private key appears to be encrypted.
Enter EXISTING password for the private key: your_key_passphrase
```

## Output

The script creates a `.p12` file such as:

```text
client.p12
```

This file can then be imported into Burp Suite:

- Settings -> Network -> TLS -> Client TLS Certificates
- Add a rule for the target hostname
- Select the generated `.p12` file
- Enter the same password used during export

## Notes

- The script does not modify the original certificate or key files.
- The certificate and key must be a valid pair; otherwise the script exits with an error.
- If your certificate chain contains intermediate certificates, the script can include them in the final bundle.
- The generated PKCS#12 file is set to be reasonably restricted on Unix-like systems (`chmod 600` when possible).

## Project files

- `burp_client_p12_generator.py` — main script
- `README.md` — project documentation

## License

This project does not currently declare a license. If you plan to redistribute or reuse it publicly, add an appropriate open-source license file.
