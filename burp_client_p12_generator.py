#!/usr/bin/env python3
"""Create a Burp Suite-compatible PKCS#12 client certificate file.

This script asks for:
1. Client certificate file path
2. Private key file path
3. New password for the generated PKCS#12 file

It then validates the certificate and key, checks that they match,
normalizes them, and creates a valid client.p12 that Burp Suite can use
for client TLS certificates.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def print_error(message: str) -> None:
    print(f"\n[ERROR] {message}")


def fail(message: str) -> None:
    print_error(message)
    raise SystemExit(1)


def run_openssl(
    args: list[str],
    *,
    input_text: str | None = None,
    binary_output: bool = False,
) -> subprocess.CompletedProcess:
    if shutil.which("openssl") is None:
        fail("OpenSSL is not installed or is not in PATH.")

    try:
        return subprocess.run(
            ["openssl", *args],
            input=input_text.encode() if binary_output and input_text is not None else input_text,
            text=not binary_output,
            capture_output=True,
            check=False,
        )
    except Exception as exc:  # pragma: no cover
        fail(f"Failed to run OpenSSL: {exc}")


def ask_file(prompt: str) -> Path:
    while True:
        value = input(prompt).strip().strip('"').strip("'")
        if not value:
            print("[!] Please enter a file path.")
            continue

        path = Path(value).expanduser().resolve()
        if not path.is_file():
            print(f"[!] File not found: {path}")
            continue
        return path


def ask_password(prompt: str) -> str:
    while True:
        pwd = input(prompt)
        if not pwd.strip():
            print("[!] Password cannot be empty.")
            continue
        return pwd


def detect_cert_format(cert_path: Path) -> str:
    data = cert_path.read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in data:
        return "PEM"

    result = run_openssl(["x509", "-inform", "DER", "-in", str(cert_path), "-noout"])
    if result.returncode == 0:
        return "DER"

    return "UNKNOWN"


def detect_key_format(key_path: Path) -> str:
    data = key_path.read_bytes()
    markers = [
        b"-----BEGIN PRIVATE KEY-----",
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
        b"-----BEGIN RSA PRIVATE KEY-----",
        b"-----BEGIN EC PRIVATE KEY-----",
        b"-----BEGIN DSA PRIVATE KEY-----",
    ]
    if any(marker in data for marker in markers):
        return "PEM"

    result = run_openssl(["pkey", "-inform", "DER", "-in", str(key_path), "-noout"])
    if result.returncode == 0:
        return "DER"

    return "UNKNOWN"


def certificate_info(cert_path: Path, cert_format: str) -> str:
    cmd = ["x509", "-in", str(cert_path), "-noout", "-subject", "-issuer", "-dates", "-serial"]
    if cert_format == "DER":
        cmd[1:1] = ["-inform", "DER"]
    result = run_openssl(cmd)
    if result.returncode != 0:
        fail(f"The certificate could not be parsed:\n{result.stderr.strip()}")
    return result.stdout.strip()


def verify_certificate(cert_path: Path, cert_format: str) -> None:
    """Step 1: verify the certificate can be read and print the key details."""
    print("\n[1] Verifying certificate...")
    result = run_openssl([
        "x509",
        "-in", str(cert_path),
        "-noout",
        "-subject",
        "-issuer",
        "-dates",
    ])

    if result.returncode != 0:
        fail(f"Certificate verification failed:\n{result.stderr.strip()}")

    print("[+] Certificate is readable.")
    print(result.stdout.strip())

    # Also run the general cert info check used later
    cert_info_text = certificate_info(cert_path, cert_format)
    print("[+] Certificate summary:")
    print(cert_info_text)


def verify_private_key(key_path: Path, key_format: str, password: str | None = None) -> tuple[bool, str | None]:
    """Step 2: verify the private key can be read and optionally unlock it."""
    print("\n[2] Verifying private key...")
    cmd = ["pkey", "-in", str(key_path), "-noout"]
    if key_format == "DER":
        cmd[1:1] = ["-inform", "DER"]
    if password is not None:
        cmd += ["-pass", f"pass:{password}"]

    result = run_openssl(cmd)
    if result.returncode == 0:
        print("[+] Private key is readable.")
        return True, None

    error_text = (result.stderr or "").lower()
    if (
        "bad decrypt" in error_text
        or "bad password" in error_text
        or "unable to load key" in error_text
        or "pass phrase" in error_text
        or "password" in error_text
        or "encrypted private key" in error_text
    ):
        print("[!] Private key is encrypted or requires a password.")
        return False, "encrypted"

    return False, (result.stderr or result.stdout or "Unknown private key error").strip()


def key_is_valid(key_path: Path, key_format: str, password: str | None = None) -> tuple[bool, str | None]:
    cmd = ["pkey", "-in", str(key_path), "-noout"]
    if key_format == "DER":
        cmd[1:1] = ["-inform", "DER"]
    if password is not None:
        cmd += ["-pass", f"pass:{password}"]

    result = run_openssl(cmd)
    if result.returncode == 0:
        return True, None

    error_text = (result.stderr or "").lower()
    if (
        "bad decrypt" in error_text
        or "bad password" in error_text
        or "unable to load key" in error_text
        or "pass phrase" in error_text
        or "password" in error_text
        or "encrypted private key" in error_text
    ):
        return False, "encrypted"

    return False, (result.stderr or result.stdout or "Unknown private key error").strip()


def normalize_certificate(cert_path: Path, cert_format: str, output_path: Path) -> None:
    cmd = ["x509", "-in", str(cert_path), "-out", str(output_path)]
    if cert_format == "DER":
        cmd[1:1] = ["-inform", "DER"]

    result = run_openssl(cmd)
    if result.returncode != 0:
        fail(f"The certificate could not be normalized:\n{result.stderr.strip()}")


def normalize_private_key(key_path: Path, key_format: str, output_path: Path, password: str | None = None) -> None:
    cmd = ["pkey", "-in", str(key_path), "-out", str(output_path)]
    if key_format == "DER":
        cmd[1:1] = ["-inform", "DER"]
    if password is not None:
        cmd += ["-pass", f"pass:{password}"]

    result = run_openssl(cmd)
    if result.returncode != 0:
        fail(f"The private key could not be normalized:\n{result.stderr.strip()}")


def extract_public_key_hash_from_cert(cert_pem: Path) -> str:
    result = run_openssl(["x509", "-in", str(cert_pem), "-pubkey", "-noout"])
    if result.returncode != 0:
        fail(f"Could not extract public key from certificate:\n{result.stderr.strip()}")

    temp_pub = cert_pem.with_name("cert_public_key.pem")
    temp_pub.write_text(result.stdout, encoding="utf-8")
    try:
        der_result = run_openssl(
            ["pkey", "-pubin", "-in", str(temp_pub), "-outform", "DER"],
            binary_output=True,
        )
        if der_result.returncode != 0:
            fail(f"Could not convert certificate public key to DER:\n{der_result.stderr.strip()}")
        return hashlib.sha256(der_result.stdout).hexdigest()
    finally:
        if temp_pub.exists():
            temp_pub.unlink()


def extract_public_key_hash_from_key(key_pem: Path) -> str:
    result = run_openssl(["pkey", "-in", str(key_pem), "-pubout"])
    if result.returncode != 0:
        fail(f"Could not extract public key from private key:\n{result.stderr.strip()}")

    temp_pub = key_pem.with_name("key_public_key.pem")
    temp_pub.write_text(result.stdout, encoding="utf-8")
    try:
        der_result = run_openssl(
            ["pkey", "-pubin", "-in", str(temp_pub), "-outform", "DER"],
            binary_output=True,
        )
        if der_result.returncode != 0:
            fail(f"Could not convert private key public key to DER:\n{der_result.stderr.strip()}")
        return hashlib.sha256(der_result.stdout).hexdigest()
    finally:
        if temp_pub.exists():
            temp_pub.unlink()


def check_certificate_dates(cert_pem: Path) -> None:
    result = run_openssl(["x509", "-in", str(cert_pem), "-checkend", "0", "-noout"])
    if result.returncode == 0:
        print("[+] Certificate is currently valid.")
    else:
        print("[!] Warning: certificate is expired or not yet valid.")


def check_eku(cert_pem: Path) -> None:
    result = run_openssl(["x509", "-in", str(cert_pem), "-noout", "-ext", "extendedKeyUsage"])
    text = (result.stdout or "").strip()
    if result.returncode == 0 and text:
        print("[+] Extended Key Usage:")
        print(text)
        if re.search(r"Client Authentication|clientAuth|TLS Web Client Authentication", text, re.IGNORECASE):
            print("[+] Client Authentication EKU detected.")
        else:
            print("[!] Warning: Client Authentication EKU not detected.")
    else:
        print("[!] Extended Key Usage not present or not readable.")


def extract_chain(cert_path: Path, workdir: Path) -> Path | None:
    try:
        cert_text = cert_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None

    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", cert_text, flags=re.DOTALL)
    if len(blocks) <= 1:
        return None

    chain_path = workdir / "chain.pem"
    chain_path.write_text("\n".join(blocks[1:]) + "\n", encoding="utf-8")
    print(f"[+] Found {len(blocks)} certificates in the certificate file; including {len(blocks) - 1} as chain.")
    return chain_path


def create_pkcs12(cert_pem: Path, key_pem: Path, chain_pem: Path | None, output_path: Path, p12_password: str) -> None:
    cmd = [
        "pkcs12",
        "-export",
        "-out", str(output_path),
        "-in", str(cert_pem),
        "-inkey", str(key_pem),
        "-name", "Burp-mTLS-client",
        "-password", f"pass:{p12_password}",
    ]
    if chain_pem is not None:
        cmd += ["-certfile", str(chain_pem)]

    result = run_openssl(cmd)
    if result.returncode != 0:
        fail(f"PKCS#12 creation failed:\n{result.stderr.strip()}")


def verify_pkcs12(output_path: Path, p12_password: str) -> None:
    result = run_openssl([
        "pkcs12",
        "-in", str(output_path),
        "-info",
        "-noout",
        "-password", f"pass:{p12_password}",
    ])
    if result.returncode != 0:
        fail(f"Generated PKCS#12 file could not be verified:\n{result.stderr.strip()}")

    combined = ((result.stdout or "") + (result.stderr or "")).lower()
    if "private key" in combined:
        print("[+] Private key confirmed in PKCS#12.")
    else:
        print("[!] Warning: Private key not clearly reported by OpenSSL verification.")

    if "certificate" in combined:
        print("[+] Certificate confirmed in PKCS#12.")
    else:
        print("[!] Warning: Certificate not clearly reported by OpenSSL verification.")


def main() -> None:
    print("=" * 80)
    print("Burp Suite mTLS PKCS#12 Creator")
    print("=" * 80)
    print("This script will ask for:")
    print("- client certificate file path")
    print("- private key file path")
    print("- new password for the generated .p12 file")
    print("It will then validate the files and create a Burp-compatible client.p12.")
    print("\nNo original certificate or key files are modified.\n")

    cert_path = ask_file("Enter CLIENT CERTIFICATE path: ")
    key_path = ask_file("Enter PRIVATE KEY path: ")
    p12_password = ask_password("Enter NEW password for generated .p12 file: ")

    print("\n[*] Detecting certificate format...")
    cert_format = detect_cert_format(cert_path)
    print(f"[+] Certificate format: {cert_format}")
    if cert_format == "UNKNOWN":
        fail("Certificate is not recognized as a PEM or DER X.509 certificate.")

    print("[*] Detecting private key format...")
    key_format = detect_key_format(key_path)
    print(f"[+] Private key format: {key_format}")
    if key_format == "UNKNOWN":
        fail("Private key is not recognized as a supported PEM or DER key.")

    # Validate cert and key
    verify_certificate(cert_path, cert_format)
    check_certificate_dates(cert_path)
    check_eku(cert_path)

    print("\n[*] Checking private key...")
    key_password = None
    key_ok, key_status = verify_private_key(key_path, key_format)
    if not key_ok:
        if key_status == "encrypted":
            print("[!] Private key appears to be encrypted.")
            key_password = input("Enter EXISTING password for the private key: ").strip()
            if not key_password:
                fail("The private key password cannot be empty.")
            key_ok, key_status = key_is_valid(key_path, key_format, key_password)
            if not key_ok:
                fail(f"The private key password is incorrect or the key could not be read:\n{key_status}")
        else:
            fail(f"The private key could not be parsed:\n{key_status}")
    print("[+] Private key parsed successfully.")

    print("\n[*] Checking whether certificate and private key match...")
    with tempfile.TemporaryDirectory(prefix="burp_p12_") as tmp_dir:
        workdir = Path(tmp_dir)
        cert_pem = workdir / "certificate.pem"
        key_pem = workdir / "private_key.pem"

        normalize_certificate(cert_path, cert_format, cert_pem)
        normalize_private_key(key_path, key_format, key_pem, key_password)

        cert_hash = extract_public_key_hash_from_cert(cert_pem)
        key_hash = extract_public_key_hash_from_key(key_pem)
        print(f"[+] Certificate public key SHA-256: {cert_hash}")
        print(f"[+] Private key public key SHA-256: {key_hash}")

        if cert_hash != key_hash:
            fail("The certificate and private key do not match. Please provide the correct pair.")

        print("[+] Certificate and private key match.")

        chain_pem = extract_chain(cert_path, workdir)

        default_output = Path.cwd() / "client.p12"
        out_value = input(f"\nOutput .p12 path [default: {default_output}]: ").strip().strip('"').strip("'")
        output_path = Path(out_value).expanduser().resolve() if out_value else default_output.resolve()

        if output_path.exists():
            confirm = input(f"[!] {output_path} already exists. Overwrite? [y/N]: ").strip().lower()
            if confirm != "y":
                fail("Operation cancelled to avoid overwriting an existing file.")
            output_path.unlink()

        output_path.parent.mkdir(parents=True, exist_ok=True)

        print("\n[*] Creating PKCS#12 file...")
        create_pkcs12(cert_pem, key_pem, chain_pem, output_path, p12_password)

        try:
            os.chmod(output_path, 0o600)
        except OSError:
            pass

        print(f"[+] PKCS#12 file created: {output_path}")
        verify_pkcs12(output_path, p12_password)

    print("\n" + "=" * 80)
    print("SUCCESS")
    print("=" * 80)
    print(f"Generated file: {output_path}")
    print("Password: the NEW password you entered for this PKCS#12 file")
    print("\nUse this in Burp Suite:")
    print("Settings -> Network -> TLS -> Client TLS Certificates")
    print("Add the certificate rule for your API hostname")
    print("Select the created .p12 file and enter the same password")
    print("=" * 80)


if __name__ == "__main__":
    main()
