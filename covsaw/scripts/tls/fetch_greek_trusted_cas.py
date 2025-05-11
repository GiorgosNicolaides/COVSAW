import requests # type: ignore
from lxml import etree # type: ignore

# URL for Greece (EL) Trusted List XML
URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"

# Namespaces used in ETL
NAMESPACES = {
    'tsl': 'http://uri.etsi.org/02231/v2#',
    'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
    'ds': 'http://www.w3.org/2000/09/xmldsig#'
}

def get_country_tsl_url(country_code):
    # Download EU list of TSLs
    response = requests.get(URL)
    xml = etree.fromstring(response.content)

    # Find the country-specific TSL URL
    for pointer in xml.xpath('//tsl:OtherTSLPointer', namespaces=NAMESPACES):
        cc = pointer.xpath('.//tsl:SchemeTerritory/text()', namespaces=NAMESPACES)
        if cc and cc[0] == country_code:
            tsl_url = pointer.xpath('.//tsl:TSLLocation/text()', namespaces=NAMESPACES)
            return tsl_url[0] if tsl_url else None
    return None

def fetch_trusted_cas_for_country(country_code='EL'):
    tsl_url = get_country_tsl_url(country_code)
    if not tsl_url:
        print(f"No TSL found for country code {country_code}")
        return []

    print(f"Fetching TSL from: {tsl_url}")
    response = requests.get(tsl_url)
    xml = etree.fromstring(response.content)

    # Extract CA names
    cas = []
    for tsp in xml.xpath('//tsl:TrustServiceProvider', namespaces=NAMESPACES):
        name = tsp.xpath('.//tsl:Name/text()', namespaces=NAMESPACES)
        if name:
            cas.append(name[0])

    return cas

greek_cas = fetch_trusted_cas_for_country('EL')

# Save to file
with open("greek_trusted_cas.txt", "w", encoding='utf-8') as f:
    for ca in greek_cas:
        f.write(ca + '\n')

print("Trusted Greek CAs saved to greek_trusted_cas.txt")
