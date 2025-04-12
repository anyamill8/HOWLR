###################################################################################
# Given an IP address, convert to IP /24 prefix and search using Censys database to
# enumerate avaliable ports/services. Only search port 443 and request SSL/TLS info. 
# Returns total number of results and port/service distribution  as well IP addresses 
# that have a direct and verifyable certificate within the IP prefix. 
# Do not attemt to collect "indirect" or "reverse DNS" certificates.
# All information uploaded to a mongoDB collection.
###################################################################################
# Prompt program by entering any IPv4 address as a command line argument.
###################################################################################

import ipaddress
import ssl
import socket
from censys.search.v2 import CensysHosts
from collections import Counter
from pymongo import MongoClient
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend
import sys
import base64
from datetime import datetime, timezone

# Censys API config
API_ID = # PLACE PERSONAL CENSYS ID HERE!
API_SECRET = # PLACE PERSONAL CENSYS SECRET HERE!

# Initialize CensysHosts object
censys_hosts = CensysHosts(api_id=API_ID, api_secret=API_SECRET)

# MongoDB config and initialization
mongo_uri = # PLACE PERSONAL MONGO URI HERE!
client = MongoClient(mongo_uri)
db = client["PLACE_NAME_HERE"]

# Converts IP address to /24 prefix
def ip_to_prefix(ip):
    network = ipaddress.ip_network(f"{ip}/24", strict=False)
    return str(network)

# Extract censys certificate public key info as PEM encoding
def extract_public_key_from_censys(parsed_public_key):
    try:
        # Ensure 'parsed_public_key' is a dictionary
        if not isinstance(parsed_public_key, dict):
            print(f"Unexpected public key format: {parsed_public_key} (type: {type(parsed_public_key)})")
            return None

        # Retrieve the key algorithm
        key_algorithm = parsed_public_key.get("key_algorithm")

        # Handle RSA Public Keys
        if key_algorithm == "RSA":
            # Decode Base64 values for modulus and exponent
            modulus_base64 = parsed_public_key["rsa"]["modulus"]
            exponent_base64 = parsed_public_key["rsa"]["exponent"]

            modulus = int.from_bytes(base64.b64decode(modulus_base64), byteorder="big")
            exponent = int.from_bytes(base64.b64decode(exponent_base64), byteorder="big")

            rsa_public_key = rsa.RSAPublicNumbers(e=exponent, n=modulus).public_key(default_backend())
            public_key_pem = rsa_public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")

        # Handle ECDSA Public Keys
        elif key_algorithm == "ECDSA":
            curve_name = parsed_public_key["ecdsa"]["curve"]
            if curve_name == "P-256":
                curve = ec.SECP256R1()
            elif curve_name == "P-384":
                curve = ec.SECP384R1()
            elif curve_name == "P-521":
                curve = ec.SECP521R1()
            else:
                raise ValueError(f"Unsupported curve: {curve_name}")
            
            x = int.from_bytes(base64.b64decode(parsed_public_key["ecdsa"]["x"]), byteorder="big")
            y = int.from_bytes(base64.b64decode(parsed_public_key["ecdsa"]["y"]), byteorder="big")
            ec_public_key = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=curve).public_key(default_backend())
            public_key_pem = ec_public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")

        # Handle other key types (currently unsupported)
        else:
            raise ValueError(f"Unsupported key algorithm: {key_algorithm}")
        
        # Remove the headers and newlines
        public_key_base64 = public_key_pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "")

        return public_key_base64

    except Exception as e:
        print(f"Failed to extract and encode public key: {e}")
        return None

# Extracts live certificate details (subject, issuer, public key, fingerprint, expiration) into a dictionary
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
        "not_valid_before (UTC)": cert.not_valid_before_utc,
        "not_valid_after (UTC)": cert.not_valid_after_utc,
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "public_key": public_key_base64
    }


# Fetch certificate information for a given IP and port
def fetch_live_certificate(ip, port, censys_certificate=None):
    try:
        # Attempt direct certificate retrieval
        context = ssl.create_default_context()
        context.check_hostname = False  # Disable hostname check as IP will not match domain name

        # Fetch direct certificate
        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=None) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    # Check if the certificate is expired
                    current_time = datetime.now(timezone.utc)
                    if cert.not_valid_before_utc > current_time or cert.not_valid_after_utc < current_time:
                        print(f"Certificate for {ip}:{port} is expired.")
                        return None
                    # Extract certificate details
                    live_cert_details = extract_cert_details(cert)

                    # Compare with Censys certificate if provided
                    labels = []
                    if censys_certificate:
                        censys_key = censys_certificate.get("public_key")
                        censys_fingerprint = censys_certificate.get("fingerprint_sha256")

                        # Check for key mismatch
                        if censys_key and (censys_key != live_cert_details["public_key"]):
                            labels.append("NoCensysKeyMatch")

                        # Check for fingerprint mismatch
                        if censys_fingerprint and (censys_fingerprint != live_cert_details["fingerprint_sha256"]):
                            labels.append("NoCensysFingerMatch")

                    # Add labels to the live_cert_details if there is a mismatch
                    live_cert_details["labels"] = labels
                    
                    return {
                        "type": "direct_cert",
                        "certificate": live_cert_details
                    }
    except Exception as e:
        print(f"No direct certificate found for {ip}:{port}. Error: {e}")

    # If no certificates are found at all, return None
    return None

# Fetch services and attempt to retrieve certificate information for each port
def fetch_services(ip):
    try:
        # Fetch censys search results for the given IP
        result = censys_hosts.view(ip)

        # Extract ASN, location details from IP
        asn_info = result.get("autonomous_system", {})
        asn = asn_info.get("asn")
        asn_name = asn_info.get("name")
        country = result.get("location", {}).get("country")

        # Store details about each service hosted on IP
        services_data = result.get("services", [])
        services = []

        # Separate port 443 and other services for prioritized processing
        port_443_service = None
        other_services = []

        for service in services_data:
            if isinstance(service, dict):
                if service.get("port") == 443:
                    port_443_service = service
                else:
                    other_services.append(service)

        # Define the order of service processing: prioritize port 443
        all_services_to_process = []
        if port_443_service:
            all_services_to_process.append(port_443_service)
        all_services_to_process.extend(other_services)

        # Collect port number, service name, transport protocol, certificate info and extended service name
        # for all IPs
        for service in all_services_to_process:
            if isinstance(service, dict):
                port = service.get("port")
                service_name = service.get("service_name")
                transport_protocol = service.get("transport_protocol")
                extended_service_name = service.get("extended_service_name")
                
                # fetch censys certificate info
                tls_data = service.get("tls", {}).get("certificates", {}).get("leaf_data", {})
                if tls_data:
                    public_key_info = tls_data.get("public_key", {})
                    censys_certificate_info = {
                        "fingerprint_sha256": tls_data.get("fingerprint"),
                        "subject": tls_data.get("subject", {}),
                        "issuer": tls_data.get("issuer", {}),
                        "not_valid_before (UTC)": tls_data.get("validity", {}).get("start"),
                        "not_valid_after (UTC)": tls_data.get("validity", {}).get("end"),
                        "public_key": extract_public_key_from_censys(public_key_info),
                        "names": tls_data.get("names", [])
                    }
                else:
                    censys_certificate_info = None
            
                # Fetch live certificate info for ONLY PORT 443
                if port == 443:
                    live_certificate_info = fetch_live_certificate(ip, port, censys_certificate_info)
                else: live_certificate_info = None

                # Add service details as a dictionary to the list
                services.append({
                    "port": port,
                    "service_name": service_name,
                    "transport_protocol": transport_protocol,
                    "extended_service_name": extended_service_name,
                    "censys_certificate": censys_certificate_info,
                    "live_certificate": live_certificate_info
                })

        return {
            "ip": ip,
            "country": country,
            "asn": asn,
            "asn_name": asn_name,
            "services": services
        }

    except Exception as e:
        print(f"Error occurred while fetching data for IP {ip}: {e}")
        return None, False

# Search services and ports across all IPs in a /24 prefix
def search_subnet(ip):
    start_time = datetime.now(timezone.utc)
    # use IP prefix to name collection in MongoDB
    network_prefix = ip_to_prefix(ip)
    collection_name = f"{network_prefix.replace("/", "_").replace(".", "_")}o4"
    collection = db[collection_name]

    # Create a collection for final statistics
    stats_collection = db["statistics"]

    # Create the IP network object for iterating over IPs in the subnet
    network = ipaddress.ip_network(network_prefix, strict=False)
    print(f"Searching all IPs in the /24 subnet: {network}")

    # Initialize counters and lists
    total_results = 0 # tracks the number of IPs in prefix running at least one service
    all_ports = [] # tracks all types of ports across all IPs
    all_services = [] # tracks all services across IPs
    ip_with_direct_cert = 0  # Tracks IPs with at least one direct_cert
    direct_cert_ips = []  # Stores IPs with at least one direct_cert

    # Iterate over each IP in the subnet
    for ip in network: # includes IPs 0-255
        print(f"\nFetching services for IP: {ip}")
        
        # Fetch services and metadata for the IP
        ip_data = fetch_services(str(ip))

        # initialize cert type for counting
        has_direct_cert = False

        # add IP with at least one open service to total results
        if ip_data and ip_data["services"]: 
            total_results += 1

            # Aggregate port and service data for statistics
            for service in ip_data["services"]:
                all_ports.append(service["port"])
                all_services.append(service["service_name"])

                # Check for specific certificate types
                live_certificate = service.get("live_certificate")
                if live_certificate:
                    if live_certificate.get("type") == "direct_cert":
                            has_direct_cert = True

            # Increment counters for specific certificate types
            if has_direct_cert:
               ip_with_direct_cert += 1
               direct_cert_ips.append(str(ip))

            # Insert data into MongoDB
            collection.insert_one(ip_data)

    # Calculate distributions
    port_distribution = Counter(all_ports)
    service_distribution = Counter(all_services)

    # Calculate runtime info 
    end_time = datetime.now(timezone.utc)
    runtime = (end_time - start_time).total_seconds()

    # Display useful port and service distribution results
    print(f"\nTotal Results: {total_results}")
    print("Port Distribution:")
    for port, count in port_distribution.items():
        print(f"  Port {port}: {count} occurrences")
    print("Service Distribution:")
    for service, count in service_distribution.items():
        print(f"  Service {service}: {count} occurrences")

    # Display the count of IPs with at least one direct cert
    print(f"Total IP addresses with at least one direct_cert: {ip_with_direct_cert}")
    
    # Print all IPs with a direct_cert
    print("\nIP addresses with at least one direct_cert:")
    for ip in direct_cert_ips:
        print(f"  {ip}")

    # Print runtime
    print(f"Runtime: {runtime}")

    # Convert keys of port_distribution and service_distribution to strings
    port_distribution_str = {str(k): v for k, v in port_distribution.items()}
    service_distribution_str = {str(k): v for k, v in service_distribution.items()}

    # Save the statistics to the MongoDB collection
    run_stats = {
        "timestamp": datetime.now(timezone.utc),
        "network_prefix": network_prefix,
        "total_results": total_results,
        "port_distribution": port_distribution_str,
        "service_distribution": service_distribution_str,
        "ip_with_direct_cert": ip_with_direct_cert,
        "direct_cert_ips": direct_cert_ips,
        "runtime_seconds": runtime
    }
    stats_collection.insert_one(run_stats)
    print(f"\nStatistics for prefix {network_prefix} saved to MongoDB collection 'statistics'")

# Use user input to inform which /24 subnet to search
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python search_subnet.py <ip_address>")
    else:
        ip_address = sys.argv[1]
        search_subnet(ip_address)
