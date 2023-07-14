#! /bin/sh
gcc -Wall -Wextra -O3 -o fsfuzz fsfuzz.c magicdata.c user_funcs.c
