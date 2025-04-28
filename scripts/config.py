import os
import dataclasses
from dotenv import load_dotenv
from utils import get_root
from database import get_number_of_malwares, get_signatures


class Enviroment():
    WINDOWS_10 = 140
    LINUX = 310


@dataclasses.dataclass(frozen=True)
class AppOptions:
    malware_bazaar_url: str =  dataclasses.field(default = "https://mb-api.abuse.ch/api/v1/")
    threat_fox_url:  str = dataclasses.field(default = "https://threatfox-api.abuse.ch/api/v1/")
    hybrid_analysis_url:  str = dataclasses.field(default = "https://www.hybrid-analysis.com/api/v2")
    virus_total_url: str = dataclasses.field(default = "https://www.virustotal.com/api/v3")
    cape_url: str = dataclasses.field(default = "http://localhost:8000/apiv2/tasks")
    timeout: int = dataclasses.field(default = 60)
    download_dir: str = dataclasses.field(default = os.path.join(get_root(), "data"))
    wazuh_dir: str = dataclasses.field(default = os.path.join(get_root(), "wazuh"))
    db_path: str = dataclasses.field(default = os.path.join(get_root(), "config", "state.db"))
    yara_file: str = dataclasses.field(default = os.path.join(get_root(), "rules.yar"))
    zip_password: str = dataclasses.field(default = "infected")
    abuse_api_key: str  = dataclasses.field(default = "")
    hybrid_analysis_api_key: str = dataclasses.field(default = "")
    virus_total_api_key: str  = dataclasses.field(default = "")
    malware_signatures: list = dataclasses.field(default_factory = list)
    number_of_malwares: int = dataclasses.field(default = 1)


    @classmethod
    def update_app_options(cls, env_file='.env'):
        env_path = os.path.join(get_root(), "config", env_file)
        load_dotenv(dotenv_path=env_path)

        return cls(
                abuse_api_key = os.getenv("abuse_api_key"),
                hybrid_analysis_api_key = os.getenv("hybrid_analysis_api_key"), 
                virus_total_api_key = os.getenv("virus_total_api_key"),
                malware_signatures = get_signatures(),
                number_of_malwares = get_number_of_malwares(),
            )


app_options = AppOptions.update_app_options()


def update_env_file(key, value, env_file='.env'):
    env_path = os.path.join(get_root(), "config", env_file)
    if os.path.exists(env_path):
        with open(env_path, 'r') as file:
            lines = file.readlines()

        found = False
        for i, line in enumerate(lines):
            if line.startswith(key + '='):
                lines[i] = f"{key}={value}\n"
                found = True
                break

        if not found:
            lines.append(f"{key}={value}\n")

        with open(env_path, 'w') as file:
            file.writelines(lines)
    else:
        with open(env_path, 'w') as file:
            file.write(f"{key}={value}\n")