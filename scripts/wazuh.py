import os
import subprocess
import sys
import shutil
import paramiko
from utils import get_root, print_message, MessageLevel, console
from config import app_options


def check_sudo():
    if os.geteuid() != 0:
        print_message("This script must be run as root or with sudo.", MessageLevel.ERROR)
        sys.exit(1)


def install_yara():
    try:
        subprocess.run(["yara", "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print_message("YARA is already installed.", MessageLevel.INFO)
        return True
    except subprocess.CalledProcessError:
        print_message("YARA not found. Installing...", MessageLevel.WARNING)
        subprocess.run(["sudo", "apt", "update"], check=True)
        result = subprocess.run(["sudo", "apt", "install", "-y", "yara"], check=True)

        if result.returncode != 0:
            print_message("Failed to install YARA.", MessageLevel.ERROR)
            return False
        print_message("YARA installed successfully.", MessageLevel.SUCCESS)
        return True


def create_sh(source: str, destination: str):
    try:
        if os.path.exists(destination):
            print_message(f"File {destination} already exists.", MessageLevel.WARNING)
            return True
        
        os.makedirs(os.path.dirname(destination), exist_ok=True)

        if not os.path.exists(source):
            print_message(f"Source file {source} does not exist.", MessageLevel.ERROR)
            return False
        
        shutil.copy(source, destination)
        
        subprocess.run(["sudo", "chown", "root:wazuh", destination], check=True)
        subprocess.run(["sudo", "chmod", "750", destination], check=True)
        print_message(f"File successfully copied and configured in {destination}", MessageLevel.SUCCESS)
        return True
    except Exception as e:
        print_message(e, MessageLevel.ERROR)
        return False


def update_config(config_file: str, directory: str):
    new_line = f'<directories realtime="yes">{directory}</directories>'

    try:
        if not os.path.exists(config_file):
            print_message(f"{config_file} does not exist.", MessageLevel.ERROR)
            return False

        with open(config_file, "r") as file:
            lines = file.readlines()

        if any(new_line in line for line in lines):
            print_message("The line already exists in the configuration file.", MessageLevel.WARNING)
            return True
        
        updated_lines = []
        syscheck_found = False

        for line in lines:
            updated_lines.append(line)
            if "<syscheck>" in line and not syscheck_found:
                updated_lines.append(f"    {new_line}\n")
                syscheck_found = True

        if not syscheck_found:
            print_message("syscheck not found.", MessageLevel.ERROR)
            return False

        with open(config_file, "w") as file:
            file.writelines(updated_lines)
        print_message("Line added to the configuration file.", MessageLevel.SUCCESS)
        return True
    except FileNotFoundError as e:
        print_message(e, MessageLevel.ERROR)
        return False
    

def restart_service(service: str, ssh=None):
    try:
        if ssh:
            stdin, stdout, stderr = ssh.exec_command(f"sudo systemctl restart {service}")
            if stdout.channel.recv_exit_status() == 0:
                print_message(f"{service} restarted successfully on remote server.", MessageLevel.SUCCESS)
            else:
                print_message(f"During {service} restart on remote server {stderr.read().decode()}", MessageLevel.ERROR)
        else:
            subprocess.run(["sudo", "systemctl", "restart", service], check=True)
            print_message(f"{service} restarted successfully on local machine.", MessageLevel.SUCCESS)
        return True
    except Exception as e:
        print_message(f"During restarting {service} {e}", MessageLevel.ERROR)
        return False


def check_and_append_file(ssh, file_path, content):
    try:
        check_command = f"sudo cat {file_path}"
        stdin, stdout, stderr = ssh.exec_command(check_command)
        output = stdout.read().decode()
        error = stderr.read().decode()

        if content in output:
            print_message(f"Content already present in file {file_path}.", MessageLevel.WARNING)
        else:
            append_command = f"echo '{content}' | sudo tee -a {file_path}"
            ssh.exec_command(append_command)
            print_message(f"Content successfully added to file {file_path}.", MessageLevel.SUCCESS)
        
    except Exception as e:
        print_message(f"In check_and_append_file: {e}.", MessageLevel.ERROR)


def generate_ssh_key(key_path="~/.ssh/id_rsa"):
    key_path = os.path.expanduser(key_path)
    if not os.path.exists(key_path):
        print_message("Generating SSH key...", MessageLevel.INFO)
        subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", key_path, "-N", ""], check=True)
    else:
        print_message(f"SSH key already exists.", MessageLevel.WARNING)
    return True


def copy_ssh_key_to_server(username, server, key_path="~/.ssh/id_rsa.pub"):
    key_path = os.path.expanduser(key_path)
    print_message(f"Copying SSH key to {server}...", MessageLevel.INFO)
    try:
        subprocess.run(["ssh-copy-id", "-i", key_path, f"{username}@{server}"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True 
    except subprocess.CalledProcessError:
        print_message(f"ssh-copy-id failed, trying manual copy...", MessageLevel.WARNING)
        try:
            with open(key_path, "r") as key_file:
                key_content = key_file.read()
            ssh_command = f"mkdir -p ~/.ssh && echo '{key_content}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && chmod 700 ~/.ssh"
            subprocess.run(["ssh", f"{username}@{server}", ssh_command], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            print_message("Manual copy also failed.", MessageLevel.ERROR)
            return False


def load_config(template_path, **kwargs):
    with open(template_path, "r", encoding="utf-8") as f:
        content = f.read()
    return content.format(**kwargs)


def check_yara_path():
    yara_path = shutil.which("yara")
    if yara_path is None:
        raise FileNotFoundError(print_message("YARA not found. Please ensure it's installed.", MessageLevel.ERROR))
    return yara_path[:yara_path.find("bin") + 3]


def check_ssh_key_exists(key_path):
    key_path = os.path.expanduser(key_path)
    if not os.path.exists(key_path):
        raise FileNotFoundError(print_message(f"The private key file '{key_path}' does not exist.", MessageLevel.ERROR))
    return key_path


def load_project_files(project_dir, directory, yara_path, rules_path):
    local_rules = load_config(os.path.join(project_dir, "wazuh", "local_rules.xml"), directory=directory)
    local_decoder = load_config(os.path.join(project_dir, "wazuh", "local_decoder.xml"))
    ossec_config = load_config(os.path.join(project_dir, "wazuh", "ossec.conf"), yara_path=yara_path, rules_path=rules_path)
    return local_rules, local_decoder, ossec_config


def establish_ssh_connection(server, username, key_path):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    private_key = paramiko.RSAKey(filename=key_path)
    print_message(f"Connecting to {server} as {username}...", MessageLevel.INFO)
    ssh.connect(server, username=username, pkey=private_key)
    return ssh


def update_remote_files(ssh, local_rules, local_decoder, ossec_config):
    files_to_update = [
        {'path': '/var/ossec/etc/rules/local_rules.xml', 'content': local_rules},
        {'path': '/var/ossec/etc/decoders/local_decoder.xml', 'content': local_decoder},
        {'path': '/var/ossec/etc/ossec.conf', 'content': ossec_config}
    ]

    for file in files_to_update:
        check_and_append_file(ssh, file['path'], file['content'])


def update_server(server, username, directory="/tmp/yara/malware", key_path="~/.ssh/id_rsa"):
    try:
        project_dir = get_root()
        yara_path = check_yara_path()
        key_path = check_ssh_key_exists(key_path)
        rules_path = os.path.join(project_dir, "rules.yar")

        local_rules, local_decoder, ossec_config = load_project_files(project_dir, directory, yara_path, rules_path)

        ssh = establish_ssh_connection(server, username, key_path)

        update_remote_files(ssh, local_rules, local_decoder, ossec_config)
        restart_service("wazuh-manager", ssh)

    except (FileNotFoundError, Exception) as e:
        print_message(e, MessageLevel.ERROR)
        return False
    finally:
        if 'ssh' in locals():
            ssh.close()
            print_message("Connection closed.", MessageLevel.INFO)
        return True


def wazuh(directory, server, username):
    check_sudo()
    with console.status("Setting malware detection with wazuh..."):
        try:
            actions = [
            lambda: install_yara(),
            lambda: create_sh(os.path.join(app_options.wazuh_dir, "yara.sh"), "/var/ossec/active-response/bin/yara.sh"),
            lambda: update_config("/var/ossec/etc/ossec.conf", directory),
            lambda: restart_service("wazuh-agent"),
            lambda: generate_ssh_key(),
            lambda: copy_ssh_key_to_server(username, server),
            lambda: update_server(server, username, directory)
            ]
            for action in actions:
                if not action():
                    exit(1)
            print_message("YARA integration with Wazuh completed successfully.", MessageLevel.SUCCESS)
        except Exception as e:
            print_message(e, MessageLevel.ERROR)
