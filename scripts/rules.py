import os
import yara
import subprocess
import random
import string
import zipfile
import sys
import shutil
from pathlib import Path
from config import app_options
from utils import get_root, print_message, MessageLevel, console


def generate_files(num_files=app_options.number_of_malwares, file_size=1024, zip_size=3):

    directory = os.path.join(get_root(), "data", "benign_files")
    os.makedirs(directory, exist_ok=True)

    for i in range(num_files):
        text = os.path.join(directory, f"text_file_{i+1}.txt")
        binary = os.path.join(directory, f"binary_file_{i+1}.bin")
        image = os.path.join(directory, f"image_{i+1}.png")
        zip_filename = os.path.join(directory, f"archive_{i+1}.zip")
        
        try:
            with open(text, "w") as file:
                file.write("".join(random.choices(string.ascii_letters + string.digits, k=file_size)))

            with open(binary, "wb") as file:
                file.write(os.urandom(1024))  
        
            with open(image, "wb") as file:
                file.write(b"\x89PNG\r\n\x1a\n" + os.urandom(1024))

            with zipfile.ZipFile(zip_filename, "w") as zipf:
                for j in range(zip_size):
                    inner_filename = f"text_in_zip_{j+1}.txt"
                    content = "".join(random.choices(string.ascii_letters + string.digits, k=zip_size // 2))
                    zipf.writestr(inner_filename, content)
        
        except Exception as e:
            print_message(e, MessageLevel.ERROR)


def test_yara_rules(rule_file, directory):
    try:
        rules = yara.compile(filepath=rule_file)
    except Exception as e:
        print_message(f"Compiling YARA rules: {e}.", MessageLevel.ERROR)
        return
    
    good_performance = True
    benign_match_count = 0
    false_negative_count = 0

    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            is_in_benign = 'benign_files' in root
            is_in_reports = 'reports' in root
            
            try:
                matches = rules.match(file_path)
                if is_in_benign and matches:
                    print_message(f"Match found in benign file {file_path}.", MessageLevel.WARNING)
                    good_performance = False
                    benign_match_count += 1
                
                # Se il file NON è in 'benign_files' o 'reports' e NON c'è un match, non va bene
                elif not (is_in_benign or is_in_reports) and not matches:
                    print_message(f"No match for file outside benign/reports {file_path}.", MessageLevel.WARNING)
                    good_performance = False
                    false_negative_count += 1

            except Exception as e:
                print_message(f"Scanning {file_path} {e}.", MessageLevel.ERROR)
                good_performance = False
    
    if good_performance:
        print_message("The rules had expected performances.", MessageLevel.SUCCESS)
    else:
        print_message(f"The rules didn't have expected performances. "
                                 f"Found {benign_match_count} false positives and {false_negative_count} false negatives.", MessageLevel.ERROR)

    if os.path.exists(os.path.join(directory, "benign_files")):
            shutil.rmtree(os.path.join(directory, "benign_files"))


def run_yara_rules(rule_file, directory):
    directory_path = Path(directory)
    do_match = False
    file_processed = 0
    file_matched = 0
    if not directory_path.exists() or not directory_path.is_dir():
        print_message(f"Directory {directory} does not exist.", MessageLevel.ERROR)
        return
    with console.status("Scanning the directory with rules..."):
        for file_path in directory_path.rglob('*'):
            if file_path.is_file():
                try:
                    file_processed += 1
                    rules = yara.compile(filepath=rule_file)
                    matches = rules.match(str(file_path))

                    if matches:
                        do_match = True
                        file_matched += 1
                        print_message(f"File {file_path} matched YARA rules {matches}", MessageLevel.INFO)
                except Exception as e:
                            print_message(e, MessageLevel.ERROR)

    if not do_match:
        print_message("No rule matched", MessageLevel.SUCCESS)
    else:
        print_message(f"{file_processed} file processed, {file_matched} file matched.", MessageLevel.SUCCESS)


def run_yargen(malware_path: str, output_file: str) -> None:
    yarGen_dir = os.path.join(get_root(), 'yarGen')
    if not os.path.exists(yarGen_dir):
        return False
    
    try:
        subprocess.run([sys.executable, 'yarGen.py', '-m', malware_path, '-o', output_file], 
                        cwd=yarGen_dir, 
                        check=True,
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL)
    except Exception as e:
        print_message(e, MessageLevel.ERROR)
        return False
    
    if not os.path.exists(output_file):
        print_message("The output file was not generated.", MessageLevel.ERROR)
        return False
    return True


def rules() -> None:
    project_dir = get_root()
    #with console.status("Generating rules with yarGen..."):
    #    if not run_yargen(os.path.join(project_dir,"data"), os.path.join(project_dir,"rules.yar")):
    #        print_message("yarGen not installed.", MessageLevel.ERROR)
    #        return False

    generate_files()
    test_yara_rules(app_options.yara_file, os.path.join(project_dir,"data"))
    return True 


def do_scan(path: str) -> None:
    run_yara_rules(app_options.yara_file, path) 
    
