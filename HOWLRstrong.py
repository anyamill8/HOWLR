#################################################################################
# Searches a given /24 IP prefix for witnesses. Eight certifiates with at least 
# two different issuing CAs must be found # in order to satisfy HOWLR Strong
# requirements. Program prefers witnesses who have a certificate issued by the 
# CA "Let's Encrypt." Returns eight IP addresses that can be reliably used as
# witnesses for given prefix.
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

# Converts IP address to /24 prefix (or IPv6 equivalent)
def ip_to_prefix(ip):
    ip_obj = ipaddress.ip_address(ip)
    if isinstance(ip_obj, ipaddress.IPv4Address):
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
    else:
        # Using /120 for IPv6 results in 256 addresses, similar to /24 in IPv4.
        network = ipaddress.ip_network(f"{ip}/120", strict=False)
    return str(network)

# Ensure 'DigiCert, Inc.' and 'DigiCert Inc' are recognized as same CA
def normalize_issuer(issuer_name):
    name = issuer_name.lower().replace(",", "").strip()
    if name in ("digicert inc", "digicert inc."):
        return "DigiCert Inc"
    return issuer_name

# Fetch issuing CA name, may be in organizationName or commonName section
def get_ca_name(issuer_dict):
    if "organizationName" in issuer_dict:
        return issuer_dict["organizationName"]
    elif "commonName" in issuer_dict:
        return issuer_dict["commonName"]
    return "Unknown"

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

# Attempts to retrieve certificate from port 443 of a given IP.
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

# Searches the entire /24 subnet for certificates.
def search_subnet(ip):
    start_time = datetime.now(timezone.utc)
    network_prefix = ip_to_prefix(ip)
    network = list(ipaddress.ip_network(network_prefix, strict=False).hosts())
    
    found_certs = []  # List of all certificate entries.
    
    random.shuffle(network)  # Randomize the order of IP addresses searched
    
    # Attempt to fetch certificate for given IP
    for ip_addr in network:
        print(f"Checking {ip_addr}...") # Helpful for debugging
        result = fetch_live_certificate(str(ip_addr))
        if result:
            cert_info = result
            # Extract issuer values and certificate info.
            issuer_values = list(cert_info["issuer"].values())
            entry = {
                "ip": str(ip_addr),
                "certificate": cert_info,
                "issuing_ca": issuer_values  
            }
            found_certs.append(entry)
            
            # Once we have at least 8 certificates, check the diversity of issuers.
            if len(found_certs) >= 8:
                unique_issuers = set()
                for cert in found_certs:
                    # normlize name of issuing CA when checking for unique issuers
                    if cert.get("issuing_ca"):
                        ca_name = normalize_issuer(get_ca_name(cert["certificate"]["issuer"]))
                        unique_issuers.add(ca_name)
                # if there are more than one issuing CA and eight certs found, prefer one of the issuers to be 'Let's Encrypt'
                if len(unique_issuers) >= 2:
                    if "Let's Encrypt" in unique_issuers:
                        print("Stop condition met: At least 8 certificates found with at least two different issuers, including 'Let's Encrypt'.")
                        break
                    else:
                        # Continue scanning if none of the issuers are 'Let's Encrypt' unless all IP addresses have been searched
                        print("8+ certificates found with 2 issuers but none is 'Let's Encrypt'. Continuing search...")
    
    # Calculate runtime
    total_runtime = (datetime.now(timezone.utc) - start_time).total_seconds()
    
    # Decide on the final 8 certificates to return (or fewer if not enough found).
    if len(found_certs) >= 8:
        # Build a dictionary to pick one certificate per unique CA from the found certificates.
        diversity_results = {}
        for cert in found_certs:
            ca = normalize_issuer(get_ca_name(cert["certificate"]["issuer"]))
            # Only store the first occurrence for each unique CA.
            if ca not in diversity_results:
                diversity_results[ca] = cert
            # Stop early if we've captured at least two unique CAs.
            if len(diversity_results) >= 2:
                break

        # Start final_results with these two diverse certificates.
        final_results = list(diversity_results.values())
        # Then fill up to 8 using the original order in found_certs.
        for cert in found_certs:
            if len(final_results) >= 8:
                break
            if cert not in final_results:
                final_results.append(cert)
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
        # print witness IPs and their issuing CA
        print("\nFinal results:")
        for r in results:
            print(r["ip"], "-", r["issuer"])
