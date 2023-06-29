import argparse
import os
import subprocess
from rich.console import Console


def get_cli_args():
    parser = argparse.ArgumentParser(description=f"Script for running end to end tests for CME")
    parser.add_argument("-t", "--target", dest="target", required=True)
    parser.add_argument("-u", "--user", "--username", dest="username", required=True)
    parser.add_argument("-p", "--pass", "--password", dest="password", required=True)
    parser.add_argument(
        "-k",
        "--kerberos",
        action="store_true",
        required=False,
        help="Use kerberos authentication",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        required=False,
        help="Display full command output",
    )
    parser.add_argument(
        "-e",
        "--errors",
        action="store_true",
        required=False,
        help="Display errors from commands",
    )

    parsed_args = parser.parse_args()
    return parsed_args


def generate_commands(args):
    lines = []

    if args.kerberos:
        kerberos = "-k"
    else:
        kerberos = ""

    file_loc = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
    commands_file = os.path.join(file_loc, "e2e_commands.txt")

    with open(commands_file) as file:
        for line in file:
            if line.startswith("#"):
                continue
            line = line.strip()
            line = line.replace("TARGET_HOST", args.target).replace("USERNAME", f'"{args.username}"').replace("PASSWORD", f'"{args.password}"').replace("KERBEROS ", kerberos)
            lines.append(line)
    return lines


def run_e2e_tests(args):
    console = Console()
    tasks = generate_commands(args)

    result = subprocess.Popen(
        "crackmapexec --version",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    version = result.communicate()[0].decode().strip()

    with console.status(f"[bold green] :brain: Running {len(tasks)} test commands for cme v{version}...") as status:
        passed = 0
        failed = 0

        while tasks:
            task = tasks.pop(0)
            result = subprocess.Popen(
                str(task),
                shell=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            # pass in a "y" for things that prompt for it (--ndts, etc)
            text = result.communicate(input=b"y")[0]
            return_code = result.returncode

            if return_code == 0:
                console.log(f"{task.strip()} :heavy_check_mark:")
                passed += 1
            else:
                console.log(f"[bold red]{task.strip()} :cross_mark:[/]")
                failed += 1

            if args.errors:
                raw_text = text.decode("utf-8")
                if "error" in raw_text.lower() or "failure" in raw_text.lower():
                    console.log(f"[bold red] Error Detected: {raw_text}")

            if args.verbose:
                # this prints sorta janky, but it does its job
                console.log(f"[*] Results:\n{text.decode('utf-8')}")
        console.log(f"Tests [bold green] Passed: {passed} [bold red] Failed: {failed}")


if __name__ == "__main__":
    parsed_args = get_cli_args()
    run_e2e_tests(parsed_args)
