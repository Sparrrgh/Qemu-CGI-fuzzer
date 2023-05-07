#!/usr/bin/python3
from time import sleep
from subprocess import Popen, PIPE
import argparse

parser = argparse.ArgumentParser(
                    prog='repro.py',
                    description='Reproduce crashes from concretized inputs',
                    epilog='Text at the bottom of help')
parser.add_argument('-f', '--filename', help='concretized input used for the crash', required=True)
parser.add_argument('-b', '--bin', help='binary to test the crash on', required=True)
parser.add_argument('-g', help='enable GDB on port 9999', action='store_true')
args = parser.parse_args()
with open(args.filename) as f: 
    contents = f.read()
    # Get body and env from file
    env, terminator, body = contents.partition("\nFUZZTERM\n")
    mod_env = dict()
    # Take enviroment variables from null-separated string
    for variable in env.split("\x00"):
        name, terminator, value = variable.partition("=")
        mod_env[name] = value
    print(f"ENV: {env}")
    print(f"Body: {body}")
    print("\nProgram output:")
    # Build popone arr, to have the correct options
    # Make it possible to just send options to qemu?
    popen_arr = ["qemu-mips", "-L", "../../../", "--strace", "-D", "reprologs.txt"]
    if args.g:
        popen_arr.extend(["-g", "9999"])
    popen_arr.append(args.bin)
    with Popen(popen_arr, env=mod_env, stdin=PIPE, stdout=PIPE) as p:
        stdout_data = p.communicate(input=body.encode("UTF-8"))[0]
        print(stdout_data.decode("UTF-8"))