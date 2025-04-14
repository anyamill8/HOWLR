#################################################################################
# Searches a given IP /24 prefix for witnesses. Three certifiates must be found
# in order to satisfy HOWLR Light Requirements. Program prefers witnesses who have
# a certificate issued by the CA "Let's Encrypt." Returns three IP addresses that
# can be reliably used as witnesses for given /24 prefix.
#################################################################################
# Prompt program by entering any IPv4 or IPv6 address as a command line argument.
#################################################################################

import ipaddress
import ssl
import socket
import sys
import random
from pymongo import MongoClient
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# Converts IP address to /24 prefix (or equivalent).
def ip_to_prefix(ip):
    ip_obj = ipaddress.ip_address(ip)
    if isinstance(ip_obj, ipaddress.IPv4Address):
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
    else:
        # Using /120 for IPv6 results in 256 addresses, similar to /24 in IPv4.
        network = ipaddress.ip_network(f"{ip}/120", strict=False)
    return str(network)

# Extracts certificate details into a dictionary.
def extract_cert_details(cert):
    subject_info = {attr.oid._name: attr.value for attr in cert.subject}
    issuer_info = {attr.oid._name: attr.value for attr in cert.issuer}
    public_key_pem = cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    # Remove header, footer, and newlines to get only the base64-encoded content 
    public_key_base64 = public_key_pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "")
    
    return {
        "subject": subject_info,
        "issuer": issuer_info,
        "not_valid_before": cert.not_valid_before_utc,
        "not_valid_after": cert.not_valid_after_utc,
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "public_key": public_key_base64
    }

# Attempts to retrieve certificate from port 443 of a given IP
def fetch_live_certificate(ip, port=443):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        
        # Handshake timeout set to 1 second, but can be adjusted
        with socket.create_connection((ip, port), timeout=1) as sock:
            with context.wrap_socket(sock, server_hostname=None) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    # Record certificate info 
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    return extract_cert_details(cert)
    except Exception as e:
        print(f"No certificate found for {ip}:{port}. Error: {e}")
    return None

# Searches entire /24 prefix for certificates
def search_subnet(ip):
    start_time = datetime.now(timezone.utc)
    network_prefix = ip_to_prefix(ip)
    network = list(ipaddress.ip_network(network_prefix, strict=False).hosts())
    
    found_certs = [] # All certs found
    le_certs = [] # Certs issued by Let's Encrypt
    
    random.shuffle(network)  # Randomize the order of IP addresses searched 
    
    # Attempt to fetch certificate for given IP
    for ip_addr in network:
        # Do not allow victim to be a witness
        if str(ip_addr) == ip:
            continue 
        print(f"Checking {ip_addr}...") # Helpful for debugging
        result = fetch_live_certificate(str(ip_addr))
        if result:
            cert_info = result
            # Extract the list of issuer values.
            issuer_names = list(cert_info["issuer"].values())
            # Create an entry with the IP, certificate details, and a separate field for issuing CA.
            entry = {"ip": str(ip_addr), "certificate": cert_info, "issuing_ca": issuer_names}
            found_certs.append(entry)
            
            # Check if the certificate was issued by "Let's Encrypt".
            if "Let's Encrypt" in issuer_names:
                le_certs.append(entry)
                if len(le_certs) == 3:
                    print("Found 3 certificates issued by 'Let's Encrypt'. Exiting search early.")
                    break  # Stop scanning once we have 3 Let's Encrypt certificates.

    # Calculate runtime
    total_runtime = (datetime.now(timezone.utc) - start_time).total_seconds()

    # Decide which results to return:
        # If we found 3 Let's Encrypt certificates, return those.
        # Otherwise, if we found at least 3 certificates overall, return the first 3.
    if len(le_certs) == 3:
        final_results = le_certs
    elif len(found_certs) >= 3:
        final_results = found_certs[:3]
    else:
        final_results = found_certs
    
    # print results and runtime
    print(f"\nTotal certificates found: {len(found_certs)}")
    print(f"Total runtime: {total_runtime} seconds")

    return final_results

# Use user input to inform which IP prefix to search
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python search_subnet.py <ip_address>")
    else:
        ip_address = sys.argv[1]
        results = search_subnet(ip_address)
        # print witness IPs
        print("Certificates were found on the following IP addresses:")
        for entry in results:
            print(entry["ip"])
          
