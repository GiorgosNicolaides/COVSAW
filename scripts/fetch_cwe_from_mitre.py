import requests
import json

url = "https://cwe-api.mitre.org/api/v1/cwe/weakness/"


def fetch_cwe_from_mitre(cwe_id):
    """

    This function fetches information about a CWE from the MITRE API using the CWE ID.

    Args:
        cwe_id (str): CWE ID to fetch information for from MITRE API
    
    Returns:
        dict: CWE information from MITRE API

    Raises:
        requests.HTTPError: If the request to the MITRE API fails

    Example:
        >>> fetch_cwe_from_mitre("CWE-79")
        {
            "data_type":
                "CWE",
            "description":
                "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                ...
        }
    
    The MITRE API documentation can be found at https://cwe.mitre.org/data/index.html
    Quick start guide: https://github.com/CWE-CAPEC/REST-API-wg/blob/main/Quick%20Start.md

    """

    response = requests.get(url + cwe_id)
    response.raise_for_status()
    return response.json()


def get_cwe_id_input():
    """
    This function takes input from the user and returns the CWE ID.

    """

    cwe_id = input("Enter the CWE ID: ")
    return cwe_id

if __name__ == "__main__":
    cwe_id = get_cwe_id_input()
    response = fetch_cwe_from_mitre(cwe_id)   
    print(response)