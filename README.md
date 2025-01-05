# QEMU CGI Fuzzer
Fuzzer for CGI binaries written using LibAFL.

> [!WARNING]  
> This fuzzer is not generalized, it was made to test the *webproc* and *webupg* executables as described in [this](https://blog.sparrrgh.me/fuzzing/embedded/2024/06/05/fuzzing-embedded-systems-2.html) article. You will need to tweak the grammar if you want significant results with other targets. For this reason I tried putting \[APPLICATION SPECIFIC\] tags wherever the code is not applicable for other targets.

I used [epi052 solutions to domenukk fuzzing101 exercises](https://github.com/epi052/fuzzing-101-solutions/) as a base for a lot of the fuzzer and took heavy inspiration from [TrackMania fuzzer](https://github.com/RickdeJager/TrackmaniaFuzzer/) for the grammar part.

This fuzzer originally used a custom version of LibAFL 0.8.2 which added support for the MIPS architecture. I ported it to work with version 0.14.1 of LibAFL with **minimal** testing.

## To build
`cargo make --makefile makefile.toml build`

## To run
Recreate the relevant directory structure of the firmware (mainly */bin*, */lib* and */usr*), inside the directory */build*.

cd in `/build`

Run the following command
`LD_LIBRARY_PATH= ./bin/qemu_mips_cgi --cores 1 --stdout ../fuzzer_logs.txt -o ../solutions  -- ./bin/qemu_mips_cgi --strace -L . -D strace_logs.txt ./usr/www/cgi-bin/webproc`

## Make file concrete
Name of binary (used in creation of grammar, especially of environment variables)
Directory containing the solutions to concretize

`./build/bin/qemu_mips_cgi --to-concrete webproc solutions`

## Reproduce a crash using repro.py
This requires `qemu-mips` installed on the system.

After concretizing the crashes as described before, 

An example command could be:

`python3 repro.py -c solutions/concrete/id\:3-5 --bin build/usr/www/cgi-bin/webproc --logfile reprologs.txt -g`

You can then use `gdb-multiarch` to debug the executable.
- Set architecture with `set arch mips`
- Set endianess with `set endian big`
- Set target with `target remote localhost:9999`