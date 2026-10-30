import subprocess

def run_command(command):
    return subprocess.Popen(command, shell=True)
