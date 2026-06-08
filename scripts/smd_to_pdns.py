import os
import sys
import requests
import ipaddress

# ==========================================
# 1. Configuration & Credentials
# ==========================================
SMD_BASE_URL = os.getenv("SMD_URL", "https://api.openchami.cluster/hsm/v2")
SMD_TOKEN = os.getenv("SMD_TOKEN", "your_jwt_access_token_here")
SMD_VERIFY_SSL = False 

PDNS_API_URL = os.getenv("PDNS_API_URL", "http://localhost:8081/api/v1/servers/localhost/zones")
PDNS_API_KEY = os.getenv("PDNS_API_KEY", "super-secret-api-key")
BASE_ZONE = os.getenv("BASE_ZONE", "system.nersc.gov.")

NETWORK_MAPPINGS = {
    "HSN": "hsn",
    "CAN": "can",
    "HMN": "oob",
    "BMC": "oob",
    "OOB": "oob"
}

# The subdomains this script is allowed to manage (used to safely isolate deletions)
MANAGED_SUFFIXES = tuple(f".{sub}.{BASE_ZONE}" for sub in NETWORK_MAPPINGS.values())

# ==========================================
# 2. PowerDNS Helper Functions
# ==========================================
def get_pdns_headers():
    return {"X-API-Key": PDNS_API_KEY, "Content-Type": "application/json"}

def fetch_all_pdns_zones():
    """Fetches all zones from PowerDNS to route PTR records to the correct reverse zone."""
    try:
        resp = requests.get(PDNS_API_URL, headers=get_pdns_headers(), timeout=10)
        resp.raise_for_status()
        return {z['name']: z['id'] for z in resp.json()}
    except Exception as e:
        print(f"[!] Failed to fetch zones from PowerDNS: {e}")
        sys.exit(1)

def fetch_zone_records(zone_id):
    """Fetches all existing RRsets for a specific zone."""
    try:
        resp = requests.get(f"{PDNS_API_URL}/{zone_id}", headers=get_pdns_headers(), timeout=10)
        resp.raise_for_status()
        return resp.json().get('rrsets', [])
    except Exception as e:
        print(f"[!] Failed to fetch records for zone {zone_id}: {e}")
        return []

def find_best_zone(domain_name, available_zones):
    """Finds the longest matching zone for a given domain name (crucial for reverse IPs)."""
    parts = domain_name.strip('.').split('.')
    for i in range(len(parts)):
        candidate = '.'.join(parts[i:]) + '.'
        if candidate in available_zones:
            return candidate
    return None

# ==========================================
# 3. OpenCHAMI Fetch & Calculate Desired State
# ==========================================
def calculate_desired_state(available_zones):
    print(f"[*] Fetching Inventory from OpenCHAMI...")
    headers = {"Authorization": f"Bearer {SMD_TOKEN}"}
    try:
        resp = requests.get(f"{SMD_BASE_URL}/Inventory/EthernetInterfaces", headers=headers, verify=SMD_VERIFY_SSL, timeout=10)
        resp.raise_for_status()
        interfaces = resp.json()
    except Exception as e:
        print(f"[!] SMD API Error: {e}")
        sys.exit(1)

    # State structure: { zone_id: { record_name: {"type": "...", "records": [...]} } }
    desired_state = {}
    interface_counters = {}

    for iface in interfaces:
        comp_id = iface.get("ComponentID")
        if not comp_id:
            continue
            
        for ip_info in iface.get("IPAddresses", []):
            ip_str = ip_info.get("IPAddress")
            net_tag = ip_info.get("Network", "").upper()
            subdomain = NETWORK_MAPPINGS.get(net_tag)
            
            if ip_str and subdomain:
                key = (comp_id, subdomain)
                idx = interface_counters.get(key, 0)
                interface_counters[key] = idx + 1
                
                # Forward FQDN formatting
                if subdomain == "hsn" or idx > 0:
                    fqdn = f"{comp_id}-{idx}.{subdomain}.{BASE_ZONE}"
                else:
                    fqdn = f"{comp_id}.{subdomain}.{BASE_ZONE}"
                
                # 1. Map Forward (A) Record
                fwd_zone = find_best_zone(fqdn, available_zones)
                if fwd_zone:
                    desired_state.setdefault(fwd_zone, {})[fqdn] = {
                        "type": "A", "content": ip_str
                    }

                # 2. Map Reverse (PTR) Record
                try:
                    reverse_name = ipaddress.ip_address(ip_str).reverse_pointer + '.'
                    rev_zone = find_best_zone(reverse_name, available_zones)
                    if rev_zone:
                        desired_state.setdefault(rev_zone, {})[reverse_name] = {
                            "type": "PTR", "content": fqdn
                        }
                    else:
                        print(f"[!] Warning: No reverse zone found in PowerDNS for {ip_str} ({reverse_name})")
                except ValueError:
                    pass # Invalid IP address format

    return desired_state

# ==========================================
# 4. Reconcile & Push to PowerDNS
# ==========================================
def synchronize_dns(available_zones, desired_state):
    for zone_name, zone_id in available_zones.items():
        desired_rrsets = desired_state.get(zone_name, {})
        existing_rrsets = fetch_zone_records(zone_id)
        
        patches = []
        
        # A. Find records to DELETE (Exists in PDNS, but not in SMD desired state)
        for rrset in existing_rrsets:
            rtype = rrset['type']
            name = rrset['name']
            
            # Only evaluate A and PTR records
            if rtype not in ["A", "PTR"]:
                continue
                
            # Safely scope deletions: Only touch records belonging to our target networks
            is_managed = False
            if rtype == "A" and name.endswith(MANAGED_SUFFIXES):
                is_managed = True
            elif rtype == "PTR" and rrset.get('records'):
                # For PTRs, check if the FQDN it points to ends with our managed suffixes
                ptr_target = rrset['records'][0]['content']
                if ptr_target.endswith(MANAGED_SUFFIXES):
                    is_managed = True

            if is_managed and name not in desired_rrsets:
                print(f" [-] Wiping orphaned record: {name} ({rtype})")
                patches.append({
                    "name": name,
                    "type": rtype,
                    "changetype": "DELETE"
                })

        # B. Find records to ADD / UPDATE
        for name, data in desired_rrsets.items():
            # PowerDNS handles idempotent REPLACE efficiently. We push all desired.
            patches.append({
                "name": name,
                "type": data["type"],
                "ttl": 300,
                "changetype": "REPLACE",
                "records": [{"content": data["content"], "disabled": False}]
            })

        # C. Push the Batch Transaction
        if patches:
            print(f"[*] Pushing {len(patches)} transactions to zone '{zone_name}'...")
            try:
                resp = requests.patch(f"{PDNS_API_URL}/{zone_id}", headers=get_pdns_headers(), json={"rrsets": patches}, timeout=10)
                resp.raise_for_status()
            except requests.exceptions.RequestException as e:
                print(f"[!] Failed to sync zone {zone_name}: {e}")
                if e.response is not None:
                    print(f"    PDNS Error: {e.response.text}")
        else:
            print(f"[*] Zone '{zone_name}' is already perfectly in sync.")

# ==========================================
# Execution Entrypoint
# ==========================================
if __name__ == "__main__":
    import urllib3
    if not SMD_VERIFY_SSL:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
    print("--- Starting OpenCHAMI to PowerDNS Hard Sync ---")
    pdns_zones = fetch_all_pdns_zones()
    desired_state = calculate_desired_state(pdns_zones)
    synchronize_dns(pdns_zones, desired_state)
    print("--- Synchronization Complete ---")
