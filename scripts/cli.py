import typer
from malwares import malwares
from reports import reports
from ioc import ioc
from database import setup_database, synchronize_database, update_number_of_malwares, add_signatures, remove_signatures
from utils import handle_autorun, validate_positive_integer
from config import update_env_file
from rules import rules, do_scan
from wazuh import wazuh


app = typer.Typer()


@app.command(name="update")
def update_options(
        abuse_api_key: str = typer.Option(None, "--api-abuse", help="Abuse.ch API"),
        hybrid_analysis_api_key: str = typer.Option(None, "--api-hybrid", help="Hybrid Analysis API"),
        virus_total_api_key: str = typer.Option(None, "--api-virus", help="VirusTotal API"),
        number_of_malwares: int = typer.Option(None, "--limit", help="Number of malwares to download" ,  callback=lambda v: validate_positive_integer(v)),
        signature: str = typer.Option(None, "--add-signature", help="Comma-separated malware signatures to add"),
        remove_signature: str = typer.Option(None, "--remove-signature", help="Comma-separated malware signatures to remove"),
) -> None:
    '''Update configuration.'''
    if any([abuse_api_key, hybrid_analysis_api_key, virus_total_api_key, number_of_malwares, signature, remove_signature]):
        options_to_update = {
            "abuse_api_key": abuse_api_key,
            "hybrid_analysis_api_key": hybrid_analysis_api_key,
            "virus_total_api_key": virus_total_api_key, 
            "limit": number_of_malwares,
            "malware_signatures": signature,
        }

        for key, value in options_to_update.items():
            if value is not None:
                if key in ["abuse_api_key", "hybrid_analysis_api_key", "virus_total_api_key"]:
                    update_env_file(key, value)
                elif key == "limit":                    
                    update_number_of_malwares(value)
                elif key == "malware_signatures":                    
                    add_signatures(value)

        if remove_signature is not None:
            remove_signatures(remove_signature)


@app.command(name="wazuh")
def enable_wazuh(
    directory: str = typer.Option(None, "--directory", help="Directory to analyze"),
    server: str = typer.Option(None, "--server", help="Wazuh server IP"),
    username: str = typer.Option(None, "--username", help="Wazuh username"),
):
    """Enable integration between Wazuh and YARA."""

    if directory is None:
        directory = typer.prompt("Enter the directory you want to analyze")
    if server is None:
        server = typer.prompt("Enter your server ip")
    if username is None:
        username = typer.prompt("Enter your username")
    wazuh(directory, server, username)

    
@app.command(name="autorun")
def manage_autorun(
    action: str = typer.Argument(None, help="Action to perform: add, remove"),
    day: str = typer.Option(None, "--day", help="Day for autorun (e.g., Mon, Tue, ...)"),
    time: str = typer.Option(None, "--time", help="Time for autorun (HH:MM)"),
):
    """Manage autorun: add or remove."""        
    handle_autorun(action, day, time)


@app.command(name="scan")
def scan_directory(
    scan_path: str = typer.Argument(None, help="Path to scan with yara rules.", case_sensitive=False)
    ):
    """Scans a directory with YARA rules."""
    do_scan(scan_path)


@app.command(name="run")
def run():
    """Runs the entire malware analysis pipeline."""
    actions = [
        setup_database(),
        synchronize_database(),
        malwares(),
        reports(),
        ioc(),
        rules()
    ]

    for action in actions:
        try:
            if not action:
                exit(1)
        except Exception as e:
            print(f"Exception in {action.__name__}: {e}")
            exit(1)