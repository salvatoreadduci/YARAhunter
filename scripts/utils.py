import pyzipper
import subprocess
import os
import sys
import shutil
import psutil
import typer
from crontab import CronTab
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
import traceback


console = Console()


def get_root():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(current_dir)


def unzip_file(filename: str,family_dir: str, zip_password: str) -> None:
    try:
        with pyzipper.AESZipFile(filename, 'r') as zip_ref:
            zip_ref.setpassword(bytes(zip_password, 'utf-8'))
            zip_ref.extractall(family_dir)
            os.remove(filename)
    except Exception as e:
        console.print(Panel(Text(f"Error during extraction: {e}", no_wrap=True, style="bold red")))


def is_32bit_elf(file_path: str) -> bool:
    if not os.path.exists(file_path):
        console.print(Panel(Text(f"Error: File {file_path} not found.", style="bold red")))
        return False
    try:
        result = subprocess.run(['readelf', '-h', file_path], capture_output=True, text=True)
        if "ELF32" in result.stdout or "Advanced Micro Devices X86-64" in result.stdout:
            return True
    except Exception as e:
        console.print(Panel(Text(f"Error checking ELF file: {e}", no_wrap=True, style="bold red")))
    return False


def recursive_extract(data: dict, values: list) -> None:
        if isinstance(data, dict):
            for key, value in data.items():
                recursive_extract(value, values)
        elif isinstance(data, list):
            for item in data:
                recursive_extract(item, values)
        else:
            values.append(str(data))


def filter_strings(data: dict, report_dir: str, sha256: str) -> None:
    extracted_values = []
    recursive_extract(data, extracted_values)
    unique_values = list(set(filter(None, extracted_values)))
    try:
        with open(os.path.join(report_dir, f"{sha256}.txt"), "w") as file:
            file.write("\n".join(unique_values))
    except IOError as e:
        console.print(Panel(Text(f"Error writing to {sha256}.txt: {e}", style="bold red")))


def handle_autorun(action: str, day: str, time: str) -> None:
    cron_command = f"{sys.executable} {os.path.abspath(__file__)}"
    hour,minute = time.split(':')
    cron_day = convert_day_to_cron(day)
    
    if not shutil.which("crontab"):
        console.print(Panel(Text("Error: 'crontab' is not installed.", style="bold red")))
        return
    
    try:
        cron = CronTab(user=True)

        if action.lower() == "add":
            for job in cron:
                if job.command == cron_command and job.minute == int(minute) and job.hour == int(hour) and job.dow == cron_day:
                    console.print(Panel(Text(f"Autorun already exists for {day} at {time}.", style="bold red")))
                    return
                
            job = cron.new(command=cron_command, comment='autorun job')
            job.minute.on(minute)
            job.hour.on(hour)
            job.dow.on(cron_day)
            cron.write()
            typer.echo(f"Autorun added for {day} at {time}.")
        
        elif action.lower() == "delete":
            for job in cron:
                if job.command == cron_command and job.minute == int(minute) and job.hour == int(hour) and job.dow == cron_day:
                    cron.remove(job)
                    cron.write()
                    typer.echo("Autorun deleted.")
                    return
            console.print(Panel(Text(f"No autorun found for {day} at {time}.", style="bold red")))
        else:
            console.print(Panel(Text(f"Invalid action. Use 'add' or 'delete'.", style="bold red")))
    
    except Exception as e:
        console.print(Panel(Text(f"Error updating crontab: {e}", style="bold red")))


def convert_day_to_cron(day: str) -> str:
    days = {
        "sun": 0, "mon": 1, "tue": 2, "wed": 3,
        "thu": 4, "fri": 5, "sat": 6
    }
    return str(days.get(day.lower(), "*"))


def validate_positive_integer(value: int) -> int:
    if value is not None and (not isinstance(value, int) or value <= 0):
        raise typer.BadParameter(f"The value must be a positive integer.")
    return value


def extract_strings(file_path):
    """ Estrae le stringhe ASCII e Unicode da un file usando 'strings' """
    try:
        result = subprocess.run(["strings", file_path], capture_output=True, text=True)
        return result.stdout.splitlines()
    except Exception as e:
        return [f"Error extracting strings from {file_path}: {e}"]


def extract_strings_from_folder(folder_path):
    """ Estrae le stringhe da tutti i file in una cartella """
    extracted_strings = {}
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            extracted_strings[file] = extract_strings(file_path)
    return extracted_strings


def extract_pcap_iocs(pcap_path):
    """ Analizza il PCAP e estrae IP e domini contattati usando tshark """
    if not os.path.exists(pcap_path):
        return {"error": "PCAP file not found"}
    
    iocs = {"domains": [], "ips": []}

    try:
        # Estrai i domini contattati
        domains = subprocess.run(
            ["tshark", "-r", pcap_path, "-Y", "dns.qry.name", "-T", "fields", "-e", "dns.qry.name"],
            capture_output=True, text=True
        ).stdout.splitlines()
        iocs["domains"] = list(set(domains))  # Rimuove duplicati

        # Estrai gli indirizzi IP contattati
        ips = subprocess.run(
            ["tshark", "-r", pcap_path, "-Y", "ip.dst", "-T", "fields", "-e", "ip.dst"],
            capture_output=True, text=True
        ).stdout.splitlines()
        iocs["ips"] = list(set(ips))  # Rimuove duplicati

    except Exception as e:
        return {"error": f"Errore nell'analisi del PCAP: {e}"}
    
    return iocs


def get_number_of_workers():
    num_cores = psutil.cpu_count(logical=False)

    if is_io_bound():
        ideal_workers = num_cores * 2
    else:
        ideal_workers = num_cores
    
    return ideal_workers

def is_io_bound():
    io_stats = psutil.disk_io_counters()
    return io_stats.read_bytes + io_stats.write_bytes > 1000000000  # Arbitrario, personalizza secondo necessità

'''
def get_optimal_worker_count():
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_usage = psutil.virtual_memory().percent

    # Se l'uso della CPU è alto o la memoria è piena, ridurre i worker
    if cpu_usage > 80 or memory_usage > 80:
        return max(1, psutil.cpu_count(logical=True) // 2)  # Ridurre i worker
    else:
        return psutil.cpu_count(logical=True)  # Aumentare i worker in base al numero di core
'''

class MessageLevel:
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"

    LEVELS = {
        INFO: {"style": "bold white", "icon": "ℹ️ ", "title": "Info"},
        SUCCESS: {"style": "bold green", "icon": "✅", "title": "Success"},
        WARNING: {"style": "bold yellow", "icon": "⚠️ ", "title": "Warning"},
        ERROR: {"style": "bold red", "icon": "❌ ", "title": "Error"},
    }


def print_message(message: str, level: str = MessageLevel.INFO, show_traceback: Exception = None):
    level_info = MessageLevel.LEVELS.get(level, MessageLevel.LEVELS[MessageLevel.INFO])  
    text = Text(f"{level_info['icon']} {level_info['title']}! {message}", style=level_info["style"], no_wrap=True)
    
    if show_traceback:
        tb_text = "".join(traceback.format_exception(None, show_traceback, show_traceback.__traceback__))
        text.append(f"\n{tb_text}", style="dim")
    
    console.print(Panel(text, expand=False))

