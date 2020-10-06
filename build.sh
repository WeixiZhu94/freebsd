#!/bin/sh

make buildkernel -j9
make installkernel -j9
cd lib/libc
make -j9
make install
cd ../../