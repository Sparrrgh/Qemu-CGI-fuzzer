CGI fuzzer

## To build
`cargo make --makefile makefile.toml build`
## To run
`LD_LIBRARY_PATH=$(pwd)/build ./build/bin/qemu_mips_cgi --cores 1  --stdout myrealtest.txt -- ./build/bin/qemu_mips_cgi -L $(pwd)/build/ -D morelogging.txt ./build/www/cgi-bin/webproc`

## Libs
