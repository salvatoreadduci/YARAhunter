import requests
import os
from config import app_options
from utils import print_message, MessageLevel, console


def collect_iocs() -> list:

    if not app_options.abuse_api_key:
        print_message("Missing API key.", MessageLevel.ERROR)
        return []
    
    payload = '{"query":"get_iocs","days":7}'
    headers = { "Auth-Key": app_options.abuse_api_key }

    try:
        response = requests.post(app_options.threat_fox_url, data=payload, headers=headers, timeout=app_options.timeout)
        response.raise_for_status()
        data = response.json()

        if not isinstance(data, dict) or "data" not in data:
            print_message("Unexpected API response format.", MessageLevel.ERROR)
            return []

        strings = [ioc['ioc'] for ioc in data.get('data', []) if 'ioc' in ioc]
        return strings
    except Exception as e:
        print_message(e, MessageLevel.ERROR)
        return []


def ioc() -> bool:
    with console.status("Collecting latest iocs..."):
        iocs = collect_iocs()
        if not iocs:
            print_message("Cannot download the latest iocs.", MessageLevel.ERROR)
            return False
        file_path = os.path.join(app_options.download_dir, 'reports', 'iocs.txt')
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
        existing_iocs = set()
        if os.path.exists(file_path):
            with open(file_path, "r") as file:
                existing_iocs = set(file.read().splitlines())

        new_iocs = [ioc for ioc in iocs if ioc not in existing_iocs]

        with open(file_path, "a") as file:
            for ioc in new_iocs:
                file.write(ioc + "\n")
        print_message(f"{len(new_iocs)} new IOCs, {len(existing_iocs)} already present IOCs.", MessageLevel.SUCCESS)
        return True
    