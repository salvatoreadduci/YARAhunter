import re
import os
import requests
import time 
import concurrent.futures
import threading
import random
import shutil
import pyzipper
from utils import filter_strings, is_32bit_elf, extract_pcap_iocs, extract_strings_from_folder, get_number_of_workers, print_message, MessageLevel, console
from database import get_malware_paths_from_db, is_report_downloaded, insert_downloaded_report
from config import app_options, Enviroment


LOOP_TIMEOUT = 600
hybrid_analysis_limit_flag = threading.Event()
virus_total_limit_flag = threading.Event()

class BaseService:
    def __init__(self, api_key, base_url, limit_flag, header_key="api-key"):
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {header_key: self.api_key}
        self.limit_flag = limit_flag

    def _handle_request(self, method, endpoint, **kwargs):
        url = f"{self.base_url}{endpoint}"
        try:
            response = requests.request(method, url, headers=self.headers, **kwargs, timeout=app_options.timeout)
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as e:
            if response.status_code == 429: 
                print_message(f"Quota limit exceeded for {self.__class__.__name__}.", MessageLevel.ERROR)
                self.limit_flag.set() 
                return {}
            print_message(f"In {self.__class__.__name__} {e}.", MessageLevel.ERROR)
        except Exception as e :
            print_message(f"{e}.", MessageLevel.ERROR)
            return {}


class HybridAnalysisService(BaseService):
    def __init__(self, api_key, base_url):
        super().__init__(api_key, base_url, hybrid_analysis_limit_flag, header_key="api-key")

    def submit_file(self, file_path, environment_id):
        if hybrid_analysis_limit_flag.is_set():
            return None

        with open(file_path, "rb") as file:
            files = {'file': file}
            data = {"environment_id": environment_id}
            response = self._handle_request("POST", "/submit/file", files=files, data=data)
            return response.get("job_id"), response.get("sha256")

    def check_status(self, job_id):
        try: 
            response = self._handle_request("GET", f"/report/{job_id}/state")
            return response.get("state") == "SUCCESS"
        except Exception as e:
            print_message(f"{e}.", MessageLevel.ERROR)
            return False

    def get_report(self, job_id):
        return self._handle_request("GET", f"/report/{job_id}/summary")


class VirusTotalService(BaseService):
    def __init__(self, api_key, base_url):
        super().__init__(api_key, base_url, virus_total_limit_flag, header_key="x-apikey")

    def submit_file(self, file_path):
        if virus_total_limit_flag.is_set():
            return None

        with open(file_path, "rb") as file:
            files = {'file': file}
            response = self._handle_request("POST", "/files", files=files)
            return response.get("data", {}).get("id")

    def check_status(self, analysis_id):
        response =  self._handle_request("GET", f"/analyses/{analysis_id}")
        status = response.get("data", {}).get("attributes", {}).get("status")
        if status  == "completed":
            url_id = response.get("data", {}).get("links", {}).get("item")
            return url_id.split("/v3")[-1]
        return None

    def get_report(self, report_url):
        return self._handle_request("GET", report_url)


class CAPEv2Service(BaseService):
    def __init__(self, api_key, base_url):
        super().__init__(api_key, base_url, None) 

    def submit_file(self, file_path, machine_name):
        with open(file_path, "rb") as file:
            files = {"file": file}
            data = {"machine": machine_name} if machine_name else {}
            response = self._handle_request("POST", "/create/file/", files=files, data=data)
            task_id = response.get("data", {}).get("task_ids", [])[0] if response.get("data", {}).get("task_ids", []) else None
            return task_id

    def check_status(self, task_id):
        response = self._handle_request("GET", f"/status/{task_id}/")
        return response.get("data")

    def _fetch_cape_data(url, file_name, is_pcap=False):
        temp_dir = os.path.join(app_options.download_dir, 'reports', 'temp')
        os.makedirs(temp_dir, exist_ok=True)
        file_path = os.path.join(temp_dir, file_name)

        try:
            response = requests.get(url, stream=True, timeout=app_options.timeout)
            response.raise_for_status()

            if "application/json" in response.headers.get("Content-Type", ""):
                data = response.json()
                print_message(f"API response is {data}", MessageLevel.WARNING)
                return None

            with open(file_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            
            if is_pcap:
                output = extract_pcap_iocs(temp_dir)
            else:
                with pyzipper.AESZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                output = extract_strings_from_folder(temp_dir)
            return output
        except Exception as e:
            print_message(f"In downloading from {url}: {e}", MessageLevel.ERROR)
            return None
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def get_report(self, task_id):
        output = {}

        endpoints = {
            "report": f"{app_options.cape_url}get/report/{task_id}/json/",
            #"iocs": f"{app_options.cape_url}get/iocs/{task_id}/detailed/",
            #"dropped_files": f"{app_options.cape_url}get/dropped/{task_id}/",
            #"process_dump_files": f"{app_options.cape_url}get/procmemory/{task_id}/",
            #"pcap": f"{app_options.cape_url}get/pcap/{task_id}/"
        }

        for key, url in endpoints.items():
            
            if key == "pcap":
                output["pcap_iocs"] = self._fetch_cape_data(url, f"pcap_{task_id}.pcap", is_pcap=True)
                
            elif key in ["dropped_files", "process_dump_files"]:  
                output[key] = self._fetch_cape_data(url, f"{key}_{task_id}.zip")
    
            else:
                output[key] = self._handle_request("GET", f"/get/report/{task_id}/json/")


def save_report(data, report_dir, hash, hybrid, cape):

    if not hybrid and not cape:
        print_message(f"The analysis of {hash} has failed.", MessageLevel.WARNING)
        return 1
    
    filter_strings(data, report_dir, hash)
    insert_downloaded_report(f"{report_dir}/{hash}.txt", hash)

    if hybrid and not cape:
        message = "has been completed only for static analysis."
    elif not hybrid and cape:
        message = "has been completed only for dynamic analysis."
    elif hybrid and cape:
        message = "has been completed."

    print_message(f"The analysis of {hash} {message}", MessageLevel.INFO)
    return 0


def download_report(hybrid_service, virus_total_service, cape_service, hash: str, report_dir: str, ha_id: str, vt_id, cape_id) -> int:
    start_time = time.time()
    hybrid_analysis_data = cape_data = vt_data = None
    cape_status = last_status = None
    vt_report_url = None

    while time.time() - start_time < LOOP_TIMEOUT:

        if ha_id:
            hybrid_analysis_data = hybrid_service.get_report(ha_id) if hybrid_service.check_status(ha_id) else None

        if vt_id:
            vt_report_url = virus_total_service.check_status(vt_id)
            vt_data = virus_total_service.get_report(vt_report_url) if vt_report_url else None

        if cape_id:
            cape_status = cape_service.check_status(cape_id)
            if cape_status != last_status or cape_status =="pending":
                last_status = cape_status
                start_time = time.time()
            if cape_status == "reported":
                cape_data = cape_service.get_report(cape_id)

        if not ha_id and not vt_id and cape_status in [None, "failed_analysis"]:
            return save_report(None, report_dir, hash, False, False)
        
        if (hybrid_analysis_data or vt_data) and cape_status in [None, "failed_analysis"]:
            return save_report(hybrid_analysis_data or vt_data, report_dir, hash, True, False)
        
        if not ha_id and not vt_id and cape_status == "reported":
            return save_report(cape_data, report_dir, hash, False, True)
        
        if (hybrid_analysis_data or vt_data) and cape_status == "reported":
            merged_data = {"hybrid_analysis_data": hybrid_analysis_data, "virus_total_data": vt_data, "cape_data": cape_data}
            return save_report(merged_data, report_dir, hash, True, True)
        
        time.sleep(random.uniform(app_options.timeout/3, app_options.timeout/2))
    print_message(f"Timeout reached for {hash}. Exiting loop.", MessageLevel.WARNING)
    return save_report(hybrid_analysis_data or vt_data or cape_data, report_dir, hash, bool(hybrid_analysis_data or vt_data), bool(cape_data))


def reports() -> bool:
    hybrid_service = HybridAnalysisService(api_key=app_options.hybrid_analysis_api_key, base_url=app_options.hybrid_analysis_url)
    virus_total_service = VirusTotalService(api_key=app_options.virus_total_api_key, base_url=app_options.virus_total_url)
    cape_service = CAPEv2Service(api_key=None, base_url=app_options.cape_url)
    report_dir = os.path.join(app_options.download_dir, 'reports')
    os.makedirs(report_dir, exist_ok=True)
    
    malware_paths = get_malware_paths_from_db()
    if not malware_paths:
        print_message("No malware path found in the database.", MessageLevel.ERROR)
        return False
    new_reports, existing_reports, skipped_reports = 0, 0, 0
    with console.status("Obtaining reports..."):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = []
        
            for path in malware_paths:

                if is_report_downloaded(path):
                    existing_reports += 1
                    continue
                
                vt_id = result = cape_id = None
                enviroment_id = Enviroment.LINUX if re.search(r'\.elf$', path) or re.search(r'\.sh$', path) else Enviroment.WINDOWS_10
                    
                if enviroment_id == Enviroment.LINUX and is_32bit_elf(path):
                    vt_id = virus_total_service.submit_file(path)
                    cape_id = cape_service.submit_file(path, "ubuntu")
                
                elif enviroment_id == Enviroment.WINDOWS_10:
                    if not hybrid_analysis_limit_flag.is_set():
                        result = hybrid_service.submit_file(path, enviroment_id)
                    elif not virus_total_limit_flag.is_set:
                        vt_id = virus_total_service.submit_file(path)
                    cape_id = cape_service.submit_file(path, "win10")

                ha_id, hash = (result if result else (None, None))
                
                if result or cape_id or vt_id:
                    if not hash:
                        match = re.search(r'.+\/(\w+)\.\w+$', path)
                        hash = match.group(1) if match else None
                    futures.append(executor.submit(download_report, hybrid_service, virus_total_service, cape_service, hash, report_dir, ha_id, vt_id, cape_id))
                else:
                    skipped_reports += 1
            time.sleep(random.uniform(app_options.timeout/2, app_options.timeout))
           
        for future in concurrent.futures.as_completed(futures):
            if future.result() == 1:
                skipped_reports += 1
            else:
                new_reports += 1

        print_message(f"{new_reports} new reports, {existing_reports} already present reports, {skipped_reports} skipped reports.", MessageLevel.SUCCESS)
        return True