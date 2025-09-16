#!/usr/bin/env python3
"""
Example code that demonstrates the py.subprocess-shell rule violation.
This code should trigger the security rule.
"""

import subprocess
import os

def unsafe_subprocess_example():
    """This function demonstrates unsafe subprocess usage with shell=True."""
    user_input = input("Enter command: ")
    result = subprocess.run(user_input, shell=True)  # This will trigger the rule
    return result

def another_unsafe_example():
    """Another example of unsafe subprocess usage."""
    command = "ls -la"
    result = subprocess.call(command, shell=True)  # This will trigger the rule
    return result

def unsafe_popen_example():
    """Example using Popen with shell=True."""
    cmd = "echo 'Hello World'"
    process = subprocess.Popen(cmd, shell=True)  # This will trigger the rule
    return process

def unsafe_check_output_example():
    """Example using check_output with shell=True."""
    command = "whoami"
    output = subprocess.check_output(command, shell=True)  # This will trigger the rule
    return output

def complex_unsafe_example():
    """Complex example with multiple unsafe subprocess calls."""
    commands = ["ls", "pwd", "whoami"]
    for cmd in commands:
        result = subprocess.run(cmd, shell=True, capture_output=True)  # This will trigger the rule
        print(result.stdout.decode())

if __name__ == "__main__":
    unsafe_subprocess_example()
    another_unsafe_example()
    unsafe_popen_example()
    unsafe_check_output_example()
    complex_unsafe_example()