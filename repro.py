#!/usr/bin/python3
from time import sleep
from subprocess import run, PIPE
import argparse

parser = argparse.ArgumentParser(
                    prog='repro.py',
                    description='Reproduce crashes from concretized inputs'
                    )
parser.add_argument('-c', '--crashfile', help='concretized crash file to use as input', required=True)
parser.add_argument('-b', '--bin', help='path to binary to test', required=True)
parser.add_argument('-r', '--rootdir', help='root directory of the firmware (default: /build)', default="build")
parser.add_argument('--logfile', help='output file containing strace information')
parser.add_argument('-g', help='enable GDB on port 9999', action='store_true')
args = parser.parse_args()
with open(args.crashfile) as f: 
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
    # Build popopen arrary, to have the correct options
    # Make it possible to just send options to qemu?
    popen_arr = ["qemu-mips", "-L", args.rootdir]
    if (args.logfile):
        popen_arr.extend(["--strace", "-D", args.logfile])
    if args.g:
        popen_arr.extend(["-g", "9999"])
    popen_arr.append(args.bin)
    p = run(popen_arr, env=mod_env, input=body, encoding="ascii", stdout=PIPE)
    print(p.stdout)