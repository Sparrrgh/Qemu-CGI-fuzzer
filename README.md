CGI fuzzer

## To build
`cargo make --makefile makefile.toml build`

## To run
Have to create `/var/pid`

cd in `/build/usr/www/cgi-bin/`

`LD_LIBRARY_PATH=../../../ ./../../../bin/qemu_mips_cgi --cores 1 --stdout ../../../../mylogs3.txt -o ../../../../solutions  -- ./../../../bin/qemu_mips_cgi --strace -L ../../../ -D ../../../../weborig.txt ./webproc`


## With no usr in path
`LD_LIBRARY_PATH=../../ ./../../bin/qemu_mips_cgi --cores 10 --stdout ../../../fuzzlogs3.txt -o ../../../solutions  -- ./../../bin/qemu_mips_cgi -L ../../ -D ../../../qemulogs3.txt ./webproc`

## Make file concrete
`./build/bin/qemu_mips_cgi --to-concrete webproc solutions`

## To repro a crash
`python3 ../../../../repro.py --filename ../../../../solutions/concrete/id\:0-7 --bin webproc`