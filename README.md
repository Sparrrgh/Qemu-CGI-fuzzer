# QEMU CGI Fuzzer
Fuzzer for CGI binaries written using LibAFL.

> [!WARNING]  
> This fuzzer is not generalized, it was made to test the *webproc* and *webupg* executables as described belonging to the DSL-3788 binary from D-Link. You will need to tweak the grammar if you want significant results with other targets. For this reason I tried putting \[APPLICATION SPECIFIC\] tags wherever the code is not applicable for other targets.

I used [epi052 solutions to domenukk fuzzing101 exercises](https://github.com/epi052/fuzzing-101-solutions/) as a base for a lot of the fuzzer and took heavy inspiration from [TrackMania fuzzer](https://github.com/RickdeJager/TrackmaniaFuzzer/) for the grammar part.

This fuzzer originally used a **custom version** of LibAFL 0.8.2 which added support for the MIPS architecture (at the time I used cargo 1.68.0-nightly). I ported it to work with version 0.14.1 of LibAFL with **minimal** testing (read, it might break).

It's development and triage of a vulnerability (for which it's still awaiting a CVE-id) found using it is described in [this blog post](https://blog.sparrrgh.me/fuzzing/embedded/2025/01/26/fuzzing-embedded-systems-2.html).

## To build
`cargo make --makefile makefile.toml build`

## To run
Recreate the relevant directory structure of the firmware (mainly */bin*, */lib* and */usr*), inside the directory */build*.

Then inside the ***/build*** directory run the following command:

`LD_LIBRARY_PATH= ./bin/qemu_mips_cgi --cores 1 --stdout ../fuzzer_logs.txt -o ../solutions  -- ./bin/qemu_mips_cgi --strace -L . -D strace_logs.txt ./usr/www/cgi-bin/webproc`

This will fuzz the executable found at ***./usr/www/cgi-bin/webproc*** and save the output of the fuzzer in a file called ***fuzzer_logs.txt***, output your crashes in the ***/solutions*** directory and output the strace logs (for **debugging** purposes, for higher perf I suggest to disable this) in ***strace_logs.txt***

## Make file concrete
The outputs aved in */solutions* is a representation of derivation trees used by **Nautilus**, it must be concretized to triage the findings.

To concretize, run the binary with the `--to-concrete` flag.

`./build/bin/qemu_mips_cgi --to-concrete <binary_name> <crash_directory>`

This will create a ***/concrete*** subdirectory in the crash directory specified, containing all the concretized crashes.

Example using *webproc*, with the default directory structure:
`./build/bin/qemu_mips_cgi --to-concrete webproc solutions`

## Reproduce a crash using repro.py
This requires `qemu-mips` installed on the system.
```
usage: repro.py [-h] -c CRASHFILE -b BIN [-r ROOTDIR] [--logfile LOGFILE] [-g]

Reproduce crashes from concretized inputs

options:
  -h, --help            show this help message and exit
  -c CRASHFILE, --crashfile CRASHFILE
                        concretized crash file to use as input
  -b BIN, --bin BIN     path to binary to test
  -r ROOTDIR, --rootdir ROOTDIR
                        root directory of the firmware (default: /build)
  --logfile LOGFILE     output file containing strace information
  -g                    enable GDB on port 999
  ```

After concretizing the crashes as described before, run the repro script.
An example command could be:

`python3 repro.py -c solutions/concrete/id\:3-5 --bin build/usr/www/cgi-bin/webproc --logfile strace_logs.txt`

You can use `gdb-multiarch` to debug the executable (if `-g` is used).
1. Set architecture with `set arch mips`
2. Set endianess with `set endian big`
3. Set target with `target remote localhost:9999`
