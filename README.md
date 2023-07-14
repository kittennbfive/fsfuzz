# fsfuzz
a tool to find individually obfuscated or encrypted filesystems in firmware dumps

## What is this?
This tool can help find *individually* obfuscated or encrypted filesystems in firmware dumps. By *individually* i mean that each filesystem is obfuscated/encrypted on its own, so you can *not* de-obfuscate/decrypt the entire dump as one file and then throw binwalk against it. Of course if you *know* the offsets and sizes of the filesystems inside the dump you can simply extract them (with `dd` or a hex-editor or ...) and then de-obfuscate/decrypt them after. However if you do *not* know the exact offsets this tool might be helpful.
  
Major limitation: You *must* provide some code to de-obfuscate/decrypt a block of data, code to be put inside `user_funcs.c`. This means that you need to know the used algorithm and key! This tool is not a magic thing that can break encryption (i am not working for the NSA).
  
This is an early release. The tool should be considered experimental (see disclaimer below).

## Licence / Legal stuff
The file "filesystems" has been stolen/borrowed from binwalk and is licenced under MIT.
All the other stuff is provided under AGPLv3+ and WITHOUT ANY WARRANTY!

## Why did you wrote this?
Because i needed it... I had some obfuscated firmware dump for which i knew the algorithm used but not where exactly the filesystems are inside the dump. Binwalk obviously didn't find anything and manual try and error is (almost) impossible, so i automated it.

## How to compile?
First you *must* fill `user_funcs.c` with your code as stated above. There are 3 functions of which only one (`user_decrypt_block()`) is mandatory. The two others can be used to allocate/free some internal buffers or stuff like this, but you can leave them empty (you will get warnings about unused arguments). Do *not* delete any unused function or change the prototypes.
  
Then compile with gcc: `gcc -Wall -Wextra -O3 -o fsfuzz fsfuzz.c magicdata.c user_funcs.c`. No external libraries needed.

## How to use?
```
usage: fsfuzz [options]

options:
	--file $name to specify input file to be examinated (MANDATORY)
	--blocksize $size to specify blocksize (default 2048)
	--nosearch to disable filesystem search
	--show-invalid to show invalid results (warning: output can be huge)
	--string "$string" to search for string in decrypted blocks
	--match-word if $string must be 0-terminated

caution: --string may miss stuff if blocksize is too small, but the bigger the blocksize the slower the program...
```

## How does it work?
The tool first puts the entire file to be examinated in memory. Then it starts at offset 0x00000000, passes `blocksize` bytes to the user-provided decryption function and looks for magic-numbers inside the decrypted data. If something valid is found a message is printed. Then the offset is incremented by 1 and the same procedure happens again, until EOF.
  
The magic-numbers, precisely the file "filesystems", where stolen from [binwalk](https://github.com/ReFirmLabs/binwalk/) and modified/extended by me. The file is licenced under MIT. Binwalk is a great tool by the way, a big thank you to all the developpers!  As i *really* didn't want to parse this file in C i wrote a Perl5-script to convert the file to some C data-structures that are compiled into the tool. The script is provided inside this repo, but you only need it if you modify the magic-file. The basic syntax of the magic-file is the same as in `man 5 magic` but has been extended by the binwalk developpers. My code (C and Perl) only understands a small subset of the entire syntax. Especially relative, indirect and calculated (at run-time) offsets are unsupported. Other stuff might be buggy because it is untested.
