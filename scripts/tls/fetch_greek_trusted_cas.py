import requests
import yaml
import xml.etree.ElementTree as ET

# URL for the EU List of Trusted Lists (LOTL)
LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
NAMESPACE = {'ns': 'http://uri.etsi.org/02231/v2#'}  # XML namespace

def fetch_xml(url):
    """Fetch XML content from a URL."""
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    return ET.fromstring(response.content)

def get_greek_tsl_url(lotl_xml):
    """Find the URL of Greece’s Trusted List from the LOTL."""
    for pointer in lotl_xml.findall(".//ns:OtherTSLPointer", NAMESPACE):
        country_name = pointer.find(".//ns:SchemeTerritory", NAMESPACE)
        if country_name is not None and country_name.text == "EL":  # "EL" = Greece
            url_elem = pointer.find(".//ns:TSLLocation", NAMESPACE)
            if url_elem is not None:
                return url_elem.text
    return None

def extract_trusted_cas(tsl_url):
    """Fetch and parse Greece's TSL to extract trusted CA names."""
    try:
        tsl_xml = fetch_xml(tsl_url)
        cas = set()
        for tsp in tsl_xml.findall(".//ns:TSPName/ns:Name", NAMESPACE):
            cas.add(tsp.text.strip())
        return cas
    except Exception as e:
        print(f"[WARNING] Failed to process {tsl_url}: {e}")
        return set()

def save_to_yaml(ca_data, filename="sources/greek_trusted_cas.txt"):
    """Save Greek CA data to a YAML file."""
    with open(filename, "w", encoding="utf-8") as file:
        yaml.dump(ca_data, file, allow_unicode=True, default_flow_style=False)

def main():
    print("[*] Fetching EU Trusted List...")
    lotl_xml = fetch_xml(LOTL_URL)
    
    print("[*] Searching for Greece’s Trusted List URL...")
    greek_tsl_url = get_greek_tsl_url(lotl_xml)
    
    if not greek_tsl_url:
        print("[ERROR] Could not find Greece’s Trusted List URL.")
        return
    
    print(f"[*] Found Greece’s Trusted List: {greek_tsl_url}")
    
    print("[*] Extracting Greek trusted CAs...")
    greek_trusted_cas = extract_trusted_cas(greek_tsl_url)
    
    print(f"[*] Found {len(greek_trusted_cas)} trusted CAs in Greece.")
    
    print("[*] Saving to greek_trusted_cas.yaml...")
    save_to_yaml(list(greek_trusted_cas))
    
    print("[✔] Done! Greek Trusted CAs stored in greek_trusted_cas.yaml.")

if __name__ == "__main__":
    main()