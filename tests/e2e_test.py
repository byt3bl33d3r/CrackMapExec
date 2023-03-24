import argparse
import os
import subprocess
from time import sleep
from rich.console import Console

# TODO IN ARG PARSE
IP = "192.168.8.96"
USER = 'Administrator'
PASSWORD = "-p Passw0rd\!"
# PASSWORD = "-H 23C36EF176F50F9483DCE5068ED64161"
KERBEROS = ""


def get_cli_args():
    parser = argparse.ArgumentParser(
        description=f"Script for running end to end tests for CME"
    )
    parser.add_argument("-t", "--target", dest="target", required=True)
    parser.add_argument("-u", "--user", "--username", dest="username", required=True)
    parser.add_argument("-p", "--pass", "--password", dest="password", required=True)
    parser.add_argument("-k", "--kerberos", action="store_true", required=False)

    args = parser.parse_args()
    return args


def generate_commands():
    args = get_cli_args()
    lines = []

    if args.kerberos:
        kerberos = "-k"
    else:
        kerberos = ""

    file_loc = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
    commands_file = os.path.join(file_loc, "e2e_commands.txt")

    with open(commands_file) as file:
        for line in file:
            line = line.strip()
            line = line.replace("TARGET", args.target) \
                .replace("USER", f"\"{args.username}\"") \
                .replace("PASSWORD", f"\"{args.password}\"") \
                .replace("KERBEROS", kerberos)
            lines.append(line)
    return lines


def run_e2e_tests():
    console = Console()
    tasks = generate_commands()

    result = subprocess.Popen("crackmapexec --version", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    version = result.communicate()[0].decode().strip()

    with console.status(f"[bold green] :brain: Running test commands for cme v{version}...") as status:
        while tasks:
            task = tasks.pop(0)
            result = subprocess.Popen(str(task), shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            # pass in a "y" for things that prompt for it (--ndts, etc)
            text = result.communicate(input=b"y")[0]
            return_code = result.returncode
            if return_code == 0:
                console.log(f"{task.strip()} :heavy_check_mark:")
            else:
                console.log(f"[bold red]{task.strip()} :cross_mark:[/]")


if __name__ == "__main__":
    run_e2e_tests()
