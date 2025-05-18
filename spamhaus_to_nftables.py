import json
import requests

def convert_json_to_nftables(url_v4, url_v6, output_file="vars/blocklist.conf"):
    try:
        # IPv4-Daten herunterladen und verarbeiten
        response_v4 = requests.get(url_v4)
        response_v4.raise_for_status()
        
        # Jede Zeile separat als JSON parsen
        ipv4_entries = []
        for line in response_v4.text.splitlines():
            line = line.strip()
            if line and not line.startswith('{"type":"metadata"'):
                try:
                    entry = json.loads(line)
                    if 'cidr' in entry:
                        ipv4_entries.append(entry)
                except json.JSONDecodeError:
                    continue
        
        # IPv6-Daten herunterladen und verarbeiten
        response_v6 = requests.get(url_v6)
        response_v6.raise_for_status()
        
        ipv6_entries = []
        for line in response_v6.text.splitlines():
            line = line.strip()
            if line and not line.startswith('{"type":"metadata"'):
                try:
                    entry = json.loads(line)
                    if 'cidr' in entry:
                        ipv6_entries.append(entry)
                except json.JSONDecodeError:
                    continue
        
        # NFTables-Regeln erstellen
        with open(output_file, "w") as f:
            f.write("# Automatically generated NFTables blocklist from Spamhaus DROP lists\n")
            f.write("# IPv4 Blocklist\n")
            f.write("define Blocklist_v4 = {\n")
            for entry in ipv4_entries:
                f.write(f"    {entry['cidr']},\n")
            f.write("}\n\n")
            
            f.write("# IPv6 Blocklist\n")
            f.write("define Blocklist_v6 = {\n")
            for entry in ipv6_entries:
                f.write(f"    {entry['cidr']},\n")
            f.write("}\n\n")
                        
        print(f"Successfully created NFTables rules in {output_file}")
        print(f"IPv4 entries: {len(ipv4_entries)}")
        print(f"IPv6 entries: {len(ipv6_entries)}")
        
    except requests.exceptions.RequestException as e:
        print(f"Error downloading JSON files: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# URLs der Spamhaus DROP-Listen
DROP_V4_URL = "https://www.spamhaus.org/drop/drop_v4.json"
DROP_V6_URL = "https://www.spamhaus.org/drop/drop_v6.json"

# Konvertierung durchführen
convert_json_to_nftables(DROP_V4_URL, DROP_V6_URL)