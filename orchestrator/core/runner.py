"""
Secure command execution module.
Uses subprocess.Popen with shell=False to run commands and streams output.
"""
import subprocess
import shlex
from . import utils
from . import parsers

def run_command(cmd_args: list, tool_name: str, display_target: str, dry_run: bool = False):
    """
    Executes a command securely and yields its output line by line.

    Args:
        cmd_args (list): The command and its arguments as a list of strings.
        tool_name (str): The name of the tool being run.
        display_target (str): The specific target for this command (e.g., a URL).
        dry_run (bool): If True, only yields the command string without running it.

    Yields:
        str: A line of output from the command's stdout/stderr.
    """
    command_str = " ".join(shlex.quote(arg) for arg in cmd_args)
    yield f"[*] [{tool_name}] -> {display_target}\n    CMD: {command_str}\n"

    if dry_run:
        yield f"    -> DRY RUN: Command not executed.\n"
        return

    try:
        # Use Popen for real-time output streaming.
        # shell=False is crucial for security.
        process = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace' # Handle potential encoding errors in tool output
        )

        # Yield each line as it is produced by the subprocess
        for line in iter(process.stdout.readline, ''):
            yield f"    [{tool_name}] {line}"

        # Explicitly close stdout before wait() to prevent pipe buffer deadlock
        process.stdout.close()
        try:
            return_code = process.wait(timeout=300)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            yield f"[!] [{tool_name}] Timed out after 300s and was killed on {display_target}.\n"
            utils.log_error(f"'{tool_name}' on '{display_target}' timed out after 300s")
            return

        if return_code == 0:
            yield f"[+] [{tool_name}] Finished successfully on {display_target}.\n"
        else:
            yield f"[!] [{tool_name}] Finished with exit code {return_code} on {display_target}.\n"
            utils.log_error(f"'{tool_name}' on '{display_target}' exited with code {return_code}")

    except FileNotFoundError:
        yield f"[!!!] FATAL: Command for '{tool_name}' not found. Is it installed and in your PATH?\n"
        utils.log_error(f"Binary for tool '{tool_name}' not found. Command: {command_str}")
    except Exception as e:
        yield f"[!!!] FATAL: An exception occurred while running '{tool_name}': {e}\n"
        utils.log_error(f"Exception for '{tool_name}' on '{display_target}': {e}")


def run_command_direct(command_str: str, tool_name: str, display_target: str, dry_run: bool = False):
    """
    Executes a command from a string (AI-generated) and yields output line by line.
    Automatically detects output files and parses results.

    Args:
        command_str (str): The full command as a string (AI-generated).
        tool_name (str): The name of the tool being run.
        display_target (str): The target for display/logging.
        dry_run (bool): If True, only yields the command string without running it.

    Yields:
        str: A line of output from the command, or StandardFinding objects after parsing.
    """
    try:
        # Parse the command string into arguments
        cmd_args = shlex.split(command_str)
        
        yield f"[*] [{tool_name}] -> {display_target}\n    CMD: {command_str}\n"

        if dry_run:
            yield f"    -> DRY RUN: Command not executed.\n"
            return

        # Use Popen for real-time output streaming
        process = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace'
        )

        # Yield each line as it is produced
        for line in iter(process.stdout.readline, ''):
            yield f"    [{tool_name}] {line}"

        # Explicitly close stdout before wait() to prevent pipe buffer deadlock
        process.stdout.close()
        try:
            return_code = process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            yield f"[!] [{tool_name}] Timed out and was killed on {display_target}.\n"
            utils.log_error(f"'{tool_name}' on '{display_target}' timed out")
            return

        if return_code == 0:
            yield f"[+] [{tool_name}] Finished successfully on {display_target}.\n"
        else:
            yield f"[!] [{tool_name}] Finished with exit code {return_code} on {display_target}.\n"
            utils.log_error(f"'{tool_name}' on '{display_target}' exited with code {return_code}")

    except FileNotFoundError as e:
        yield f"[!!!] FATAL: Command for '{tool_name}' not found. Is it installed? Error: {e}\n"
        utils.log_error(f"Binary for tool '{tool_name}' not found. Command: {command_str}")
    except Exception as e:
        yield f"[!!!] FATAL: Exception executing '{tool_name}': {e}\n"
        utils.log_error(f"Exception for '{tool_name}': {e}")
