#######################################################################################
# This script connects to a Bitcoin node via RPC and collects its list of peer IP 
# addresses. For each peer, it scans the surrounding /24 (or /120 for IPv6) subnet 
# for potential witness IPs that return verifiable SSL/TLS certificates, aiming to 
# identify witnesses that meet HOWLR’s protection criteria. Once a set of qualifying 
# witnesses is selected, the script continuously monitors their certificates for 
# changes or signs of unresponsiveness—both of which may indicate a BGP hijack. 
# If responsivenesss, certificate fingerprints, or issuing CAs change across multiple 
# witnesses within a prefix, the script alerts the user to a potential hijack in progress.
#######################################################################################
# Prompt program by entering the duration (in hours) you would like the program to run.
# You will be prompted for your Bitcoin RPC credentials.
######################################################################################

import sys
import socket
import ssl
import ipaddress
import argparse
import time
from datetime import datetime
from getpass import getpass
import concurrent.futures

# Bitcoin RPC support
try:
    from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
except ImportError:
    print("bitcoinrpc.authproxy module not found. Please install it using 'pip install python-bitcoinrpc'")
    sys.exit(1)

# Prompt user for Bitcoin RPC username, password, and specific host/port if desired
def get_rpc_credentials():
    rpc_user = input("Enter Bitcoin RPC username: ")
    rpc_password = getpass("Enter Bitcoin RPC password: ")
    rpc_host = input("Enter Bitcoin RPC host IP (default 127.0.0.1): ") or "127.0.0.1"
    rpc_port = input("Enter Bitcoin RPC port (default 8332): ") or "8332"
    return rpc_user, rpc_password, rpc_host, rpc_port

# Gather list of Bitcoin peer IP addresses using RPC API
def get_peer_ips(rpc_user, rpc_password, rpc_host, rpc_port):
    # Connect to Bitcoin RPC
    rpc_url = f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}"
    try:
        rpc_connection = AuthServiceProxy(rpc_url)
        peers = rpc_connection.getpeerinfo()
    except Exception as e:
        print(f"Error connecting to Bitcoin RPC: {e}")
        sys.exit(1)

    # Collect set of peer IP addresses
    ip_set = set()
    for peer in peers:
        addr = peer.get("addr", "")
        if addr:
            # Strip possible IPv6 brackets and extract IP portion.
            addr = addr.strip("[]")
            ip_part = addr.split(':')[0]
            ip_set.add(ip_part)
    return list(ip_set)

# Attempts to fetch certificate from given IP via port 443. Gathers certificate
# info for later reference or returns None if no certificate found
def fetch_live_certificate(ip, port=443):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        # handshake timeout set to 1 second, but can be altered
        with socket.create_connection((ip, port), timeout=1) as sock:
            with context.wrap_socket(sock, server_hostname=None) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    from cryptography.hazmat.primitives import hashes
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    issuer_info = {attr.oid._name: attr.value for attr in cert.issuer}
                    return {
                        "issuer": issuer_info,
                        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
                        "not_valid_after_utc": getattr(cert, "not_valid_after_utc", None)
                    }
    except Exception:
        return None

# Extracts CA name from organizationName or commonName entry
def get_ca_name(issuer_dict):
    if "organizationName" in issuer_dict:
        return issuer_dict["organizationName"]
    elif "commonName" in issuer_dict:
        return issuer_dict["commonName"]
    return "Unknown"

# Ensure 'DigiCert, Inc.' and 'DigiCert Inc' are recognized as same CA
def normalize_issuer(issuer_name):
    name = issuer_name.lower().replace(",", "").strip()
    if name in ("digicert inc", "digicert inc."):
        return "DigiCert Inc"
    return issuer_name

# searches subnet of a given peer IP for candidate witness IPs.
# saves certificate and issuer info for candidate witnesses. 
# attempts to provide HOWLR strong level protection, othwerwise
# attempts HOWLR light protection, otherwise classifies peer as unprotectable
# returns recommended witnesses for each peer and level of protection (if possible)
def search_witnesses_for_peer(peer_ip):
    try:
        ip_obj = ipaddress.ip_address(peer_ip)
        # search /24 prefix for IPv4 or /120 prefix for IPv6
        subnet_mask = 24 if ip_obj.version == 4 else 120
        network = ipaddress.ip_network(f"{peer_ip}/{subnet_mask}", strict=False)
    except Exception as e:
        print(f"Error forming network for peer {peer_ip}: {e}")
        return (peer_ip, "No Protection", [])
    
    # store possible witnesses
    candidate_witnesses = []
    for ip in network.hosts():
        ip_str = str(ip)
        cert = fetch_live_certificate(ip_str)
        if cert:
            ca = normalize_issuer(get_ca_name(cert["issuer"]))
            candidate_witnesses.append({
                "ip": ip_str,
                "issuer": cert["issuer"],
                "ca": ca,
                "certificate": cert
            })
    
    if not candidate_witnesses:
        return (peer_ip, "No Protection", [])
    
    # Sort candidates to prioritize those with "let's encrypt"
    sorted_candidates = sorted(candidate_witnesses, key=lambda c: (0 if "let's encrypt" in c["ca"] else 1, c["ip"]))
    unique_cas = {c["ca"] for c in sorted_candidates}
    
    # Check for HOWLR Strong protection requirements 
    if len(sorted_candidates) >= 8 and len(unique_cas) >= 2:
        selected = []
        selected.append(sorted_candidates[0])
        first_ca = sorted_candidates[0]["ca"]
        # Ensure at least one candidate from a different CA is included.
        for c in sorted_candidates[1:]:
            if c["ca"] != first_ca:
                selected.append(c)
                break
        for c in sorted_candidates:
            if len(selected) >= 8:
                break
            if c not in selected:
                selected.append(c)
        classification = "Strong Protection"
        return (peer_ip, classification, selected)
    # Check for HOWLR Light protection requirements
    elif len(sorted_candidates) >= 3:
        selected = sorted_candidates[:3]
        classification = "Lite Protection"
        return (peer_ip, classification, selected)
    # otherwise report no protection 
    else:
        return (peer_ip, "No Protection", [])

# Monitors provided witness IPs for user-specified duration, pinging every 5 seconds
# to observe any changes in certificate information. If more than one witness in a group 
# of witnesses for a single peer is unresponseive or has certificate information changed, 
# warn user. If only one witness in peer witness group has changed, update certificate info 
# for that specific witness, unless the issuing CA has changed. If issuing CA has changed in 
# updated cert, issue warning for hijack.
def monitor_witnesses(witnesses, duration_hours):
    monitor_data = {}
    prefix_groups = {}
    # Build monitoring data and group witnesses by their subnet prefix.
    for entry in witnesses:
        ip = entry['ip']
        cert = entry['certificate']
        initial_fp = cert.get("fingerprint_sha256")
        initial_ca = normalize_issuer(get_ca_name(cert["issuer"]))
        monitor_data[ip] = {
            "initial_fingerprint": initial_fp,
            "initial_ca": initial_ca,
            "last_valid": cert.get("not_valid_after"),
            "changed": False,
            "unresponsive": False,
        }
        # determine which prefix to search depending on IPv4 vs IPv6
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version == 4:
                prefix = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            else:
                prefix = str(ipaddress.ip_network(f"{ip}/120", strict=False))
        except Exception as e:
            prefix = None
        if prefix:
            prefix_groups.setdefault(prefix, []).append(ip)
    
    # set runtime duration
    duration_sec = duration_hours * 3600
    start_time = time.time()

    try:
        while time.time() - start_time < duration_sec:
            # Reset change/unresponsive flags for this round.
            for ip in monitor_data:
                monitor_data[ip]["changed"] = False
                monitor_data[ip]["unresponsive"] = False

            # Re-fetch certificate info from all witnesses
            print(f"\n[{datetime.now()}] Pinging witness IPs...")
            for ip, data in monitor_data.items():
                cert_info = fetch_live_certificate(ip)
                # if witness is not reachable, report as unresponsive
                if not cert_info:
                    print(f"Witness {ip} is unresponsive.")
                    monitor_data[ip]["unresponsive"] = True
                    continue
                # gather latest certificate fingerprint to see if cert has changed
                new_fp = cert_info.get("fingerprint_sha256")
                new_ca = normalize_issuer(get_ca_name(cert_info["issuer"]))
                if new_fp != data["initial_fingerprint"]:
                    print(f"Witness {ip} certificate fingerprint has changed.")
                    # send warning if CA has changed (a likely sign of BGP Hijack)
                    if new_ca != data["initial_ca"]:
                        print(f"ALERT: Witness {ip} certificate CA changed from {data['initial_ca']} to {new_ca}. Potential Hijack!")
                    # if cert info has changed, but issuing CA is the same, update cert info (likely valid cert has expired and been reissued)
                    else:
                        print(f"Witness {ip} certificate fingerprint changed but CA remains the same. Updating stored info.")
                        monitor_data[ip]["initial_fingerprint"] = new_fp
                        monitor_data[ip]["initial_ca"] = new_ca
                    monitor_data[ip]["changed"] = True

            # Now check each prefix group for potential hijack alerts.
            for prefix, ips in prefix_groups.items():
                group_alert_count = sum(1 for ip in ips if monitor_data[ip]["changed"] or monitor_data[ip]["unresponsive"])
                if group_alert_count > 1:
                    print(f"ALERT: In prefix {prefix}, {group_alert_count} witness IPs show changes/unresponsiveness. Potential hijack!")
            # pause pinging so that witnesses do not block HOWLR from making more requests
            time.sleep(5)
    # ensure user can end monitoring if they would like to end early
    except KeyboardInterrupt:
        print("\nMonitoring interrupted by user. Exiting.")
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(
        description="Peer Witness Analysis and Monitoring using Bitcoin RPC.\n"
                    "For each peer, the script scans its subnet for candidate witness IPs.\n"
                    "For IPv4, a /24 is scanned; for IPv6, a /120 is scanned.\n"
                    "Strong Protection requires ≥8 candidates with ≥2 unique CAs.\n"
                    "Lite Protection requires ≥3 candidates.\n"
                    "After analysis, the selected witness IPs are aggregated and monitored for certificate changes."
    )
    # Collect user-specified runtime
    parser.add_argument("--duration", type=float, required=True, help="Monitoring duration in hours.")
    args = parser.parse_args()
    monitor_duration = args.duration
    
    # gather user Bitcoin RPC credentials
    rpc_user, rpc_password, rpc_host, rpc_port = get_rpc_credentials()
    print(f"\nConnecting to Bitcoin RPC at {rpc_host}:{rpc_port} with user '{rpc_user}'...")

    # search for peers
    peer_ips = get_peer_ips(rpc_user, rpc_password, rpc_host, rpc_port)
    print(f"Retrieved {len(peer_ips)} peer IP(s).")
    if not peer_ips:
        sys.exit(1)

    # Analyze witness candidates for each peer concurrently.
    results = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_peer = {executor.submit(search_witnesses_for_peer, peer): peer for peer in peer_ips}
        for future in concurrent.futures.as_completed(future_to_peer):
            peer = future_to_peer[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as exc:
                print(f"Peer {peer} generated an exception: {exc}")

    # Report per-peer analysis and aggregate witness candidates.
    print("\nPeer Witness Protection Analysis Report:")
    aggregated_witnesses = {}
    for peer_ip, classification, witness_list in results:
        print(f"Peer {peer_ip}: {classification}")
        if witness_list:
            ips = [w["ip"] for w in witness_list]
            print("  Witness IPs:", ", ".join(ips))
            # Aggregate unique witness entries by IP.
            for w in witness_list:
                aggregated_witnesses[w["ip"]] = w  # Duplicates overwritten.
        else:
            print("  No witness candidates found.")

    if not aggregated_witnesses:
        print("No witness candidates aggregated from any peer. Exiting.")
        sys.exit(1)

    # report total number of witnesses across all peers
    final_witnesses = list(aggregated_witnesses.values())
    print(f"\nAggregated total of {len(final_witnesses)} unique witness IP(s) for monitoring.")
    
    # Begin monitoring the aggregated witness IPs.
    monitor_witnesses(final_witnesses, monitor_duration)

if __name__ == "__main__":
    main()
