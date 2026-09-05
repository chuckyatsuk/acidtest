# Vulnerable: subprocess with shell=True on user input.
import subprocess
import sys

def run(user_arg):
    subprocess.call(f"echo {user_arg}", shell=True)
