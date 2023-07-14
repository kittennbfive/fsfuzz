#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <err.h>

//You need to provide these functions!

void user_decrypt_init(const uint_fast32_t blocksize)
{
	
}

void user_decrypt_block(uint8_t * const block, const uint_fast32_t blocksize)
{
	errx(1, "user_decrypt_block is empty - you need to provide at least this function!"); //remove this line obviously...
}

void user_decrypt_cleanup(void)
{
	
}

