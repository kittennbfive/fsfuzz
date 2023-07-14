#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <err.h>

#include "magicdata.h"

/*
fsfuzz - a tool to find individually obfuscated or encrypted filesystems in firmware dumps

Version 0.1 - early release, consider with caution

You need to provide the de-obfuscation/decryption function in user_funcs.c! This means if the firmware is encrypted you *will* need the key. This tool can't crack strong (or even weak) encryption...

The filesystem-magic stuff in file "filesystems" have been stolen/borrowed from binwalk (licence: MIT). Thanks to all the contributors there! Everything else was written from scratch.

(c) 2023 by kittennbfive

https://github.com/kittennbfive

except file "filesystems" everything is licenced under AGPLv3+ and provided WITHOUT ANY WARRANTY!

Please read the fine manual.
*/

#define SZ_DATE_STR 30 //for test_convert_date(), man-page says >=26 -> should be fine
#define SZ_FILENAME_MAX 50
#define SZ_SEARCHSTRING_MAX 50
#define NB_CHARS_BEFORE_STRMATCH 10
#define NB_CHARS_AFTER_STRMATCH 10

typedef enum
{
	TEST_INVALID,
	TEST_SUCCESS,
	TEST_FAILURE
} testresult_t;


//You need to provide these, see user_funcs.c
void user_decrypt_init(const uint_fast32_t blocksize);
void user_decrypt_block(uint8_t * const block, const uint_fast32_t blocksize);
void user_decrypt_cleanup(void);


static uint64_t helper_get_value_unsigned(uint8_t const * const data, const uint_fast8_t nb_bytes, const endian_t endian)
{
	uint64_t ret=0;
	uint_fast8_t i;
	
	if(endian==ENDIAN_LE)
	{
		for(i=0; i<nb_bytes; i++)
			ret|=((uint64_t)data[i])<<(8*i);
	}
	else if(endian==ENDIAN_BE)
	{
		for(i=0; i<nb_bytes; i++)
			ret|=((uint64_t)data[i])<<(8*(nb_bytes-i-1));		
	}
	else if(endian==ENDIAN_UNDEF && nb_bytes==1)
		ret=(uint64_t)data[0];
	else
		errx(1, "helper_get_value_unsigned: undef endian for >1 byte requested");
	
	return ret;
}	

static uint64_t get_value_unsigned(uint8_t const * const data, const datatype_t type, const endian_t endian)
{
	uint64_t ret=0;
	
	switch(type)
	{
		case DATA_STRING:
		case DATA_INT8:
		case DATA_INT16:
		case DATA_INT32:
		case DATA_INT64:
			errx(1, "get_value_unsigned: requested signed or string");
			break;
		
		case DATA_DATE:
		case DATA_UDATE:
			errx(1, "get_value_unsigned: DATA_[U]DATE unimpl, call helper directly");
			break;
		
		case DATA_UINT8:
			ret=helper_get_value_unsigned(data, 1, endian);
			break;
		
		case DATA_UINT16:
			ret=helper_get_value_unsigned(data, 2, endian);
			break;
		
		case DATA_UINT32:
			ret=helper_get_value_unsigned(data, 4, endian);
			break;
		
		case DATA_UINT64:
			ret=helper_get_value_unsigned(data, 8, endian);
			break;
	}
	
	return ret;
}

static int64_t helper_get_value_signed(uint8_t const * const data, const uint_fast8_t nb_bytes, const endian_t endian)
{
	uint64_t u64=0;
	int64_t ret;
	uint_fast8_t i;
	
	if(endian==ENDIAN_LE)
	{
		for(i=0; i<nb_bytes; i++)
			u64|=((uint64_t)data[i])<<(8*i);
	}
	else if(endian==ENDIAN_BE)
	{
		for(i=0; i<nb_bytes; i++)
			u64|=((uint64_t)data[i])<<(8*(nb_bytes-i-1));		
	}
	else if(endian==ENDIAN_UNDEF && nb_bytes==1)
		ret=(int64_t)data[0];
	else
		errx(1, "helper_get_value_signed: undef endian for >1 byte requested");
	
	if(u64&(1<<(8*nb_bytes-1)))
		ret=-((u64-1)^((1ULL<<(8*nb_bytes))-1));
	else
		ret=u64;
	
	return ret;
}	

static int64_t get_value_signed(uint8_t const * const data, const datatype_t type, const endian_t endian)
{
	int64_t ret=0;
	
	switch(type)
	{
		case DATA_STRING:
		case DATA_UINT8:
		case DATA_UINT16:
		case DATA_UINT32:
		case DATA_UINT64:
			errx(1, "get_value_signed: requested unsigned or string");
			break;
		
		case DATA_DATE:
		case DATA_UDATE:
			errx(1, "get_value_signed: DATA_[U]DATE unimpl, call helper directly");
			break;
		
		case DATA_INT8:
			ret=helper_get_value_signed(data, 1, endian);
			break;
		
		case DATA_INT16:
			ret=helper_get_value_signed(data, 2, endian);
			break;
		
		case DATA_INT32:
			ret=helper_get_value_signed(data, 4, endian);
			break;
		
		case DATA_INT64:
			ret=helper_get_value_signed(data, 8, endian);
			break;
	}
	
	return ret;
}

static void test_make_message(uint8_t const * const data, const int64_t val_print, char const * const date_print, test_t const * const test, char * const message)
{
	char msg_buf[100];
	
	if(!test->flag_no_space)
		strcat(message, " ");
	if(test->message_has_argument)
	{
		if(test->data_type==DATA_STRING)
			sprintf(msg_buf, test->message, (char*)(data+test->offset));
		else if(test->data_type==DATA_DATE || test->data_type==DATA_UDATE)
			sprintf(msg_buf, test->message, date_print);
		else
			sprintf(msg_buf, test->message, val_print);
	}
	else
		sprintf(msg_buf, "%s", test->message);
	strcat(message, msg_buf);
}

static void test_convert_date(uint8_t const * const data, test_t const * const test, char * const date_str) //TODO TEST THIS (signed/unsigned)
{
	int32_t unixtime_signed;
	uint32_t unixtime_unsigned;
	int64_t unixtime64;
	
	switch(test->data_type)
	{
		case DATA_DATE: //signed
			unixtime_signed=helper_get_value_signed(data, 4, test->endian);
			unixtime64=unixtime_signed;
			break;
		
		case DATA_UDATE: //unsigned
			unixtime_unsigned=helper_get_value_unsigned(data, 4, test->endian);
			unixtime64=unixtime_unsigned;
			break;
		
		default:
			errx(1, "test_convert_data: invalid data_type");
			break;
	}
	
	ctime_r(&unixtime64, date_str);
}

static testresult_t make_test(uint8_t const * const data, test_t const * const test, const uint_fast32_t blocksize, char * const message)
{
	bool test_done=false;
	bool is_signed=false;
	bool result=false;
	bool force_true=false;
	
	int64_t val_s;
	uint64_t val_u;
	int64_t val_print=0;
	char date_str[SZ_DATE_STR];
	
	static bool warning_printed=false;
	
	if(test->offset>blocksize)
	{
		if(!warning_printed)
		{
			warning_printed=true;
			printf("warning: blocksize is to small for at least one test\n\n");
		}
		
		message[0]='\0'; //dont return any message here as it would spam the user with the same message again and again if option --show-invalid was specified
		
		return TEST_INVALID;
	}		
	
	switch(test->data_type)
	{
		case DATA_STRING:
			switch(test->test_type)
			{
				case TEST_EQUAL:
					if(!memcmp(data+test->offset, test->string.bytes, test->string.nb_bytes))
						result=true;
					break;
				
				case TEST_NOT_VALUE:
					if(memcmp(data+test->offset, test->string.bytes, test->string.nb_bytes))
						result=true;
					break;
				
				default:
					errx(1, "make_test: unimpl test for DATA_STRING");
					break;
			}
			test_done=true;
			break;
		
		case DATA_DATE:
		case DATA_UDATE:
			test_convert_date(data+test->offset, test, date_str);
			test_done=true; //FIXME add tests for this data type
			result=true;
			break;
			
		
		case DATA_INT8:
		case DATA_INT16:
		case DATA_INT32:
		case DATA_INT64:
			is_signed=true;
			break;
		
		case DATA_UINT8:
		case DATA_UINT16:
		case DATA_UINT32:
		case DATA_UINT64:
			break;
	}
	
	if(is_signed && !test_done)
	{
		val_s=get_value_signed(data+test->offset, test->data_type, test->endian);
		switch(test->operation_on_value)
		{
			case DATAOP_NONE:
				break;
			
			case DATAOP_AND:
				errx(1, "make_test: can't do DATAOP_AND on signed");
				break;
			
			case DATAOP_MULTIPLY:
				errx(1, "make_test: can't do DATAOP_MULTIPLY on signed");
				break;
		}
	}
	
	if(is_signed)
	{
		test_done=true;
		switch(test->test_type)
		{
			case TEST_TRUE:
				force_true=true;
				break;
			
			case TEST_EQUAL:
				if(val_s==test->value_signed)
					result=true;
				break;
			
			case TEST_LESS_THAN:
				if(val_s<test->value_signed)
					result=true;
				break;
			
			case TEST_MORE_THAN:
				if(val_s>test->value_signed)
					result=true;
				break;
			
			case TEST_BITS_SET:
				if((val_s&test->value_signed)==test->value_signed)
					result=true;
				break;
			
			case TEST_NOT_VALUE:
				if(val_s!=test->value_signed)
					result=true;
				break;
		}
		val_print=val_s;
	}

	if(!is_signed && !test_done)
	{
		val_u=get_value_unsigned(data+test->offset, test->data_type, test->endian);
		switch(test->operation_on_value)
		{
			case DATAOP_NONE:
				break;
			
			case DATAOP_AND:
				val_u&=test->operand;
				break;
			
			case DATAOP_MULTIPLY:
				val_u*=test->operand;
				break;
		}
	}
		
	if(!is_signed && !test_done)
	{
		test_done=true;
		switch(test->test_type)
		{
			case TEST_TRUE:
				force_true=true;
				break;
			
			case TEST_EQUAL:
				if(val_u==test->value_unsigned)
					result=true;
				break;
			
			case TEST_LESS_THAN:
				if(val_u<test->value_unsigned)
					result=true;
				break;
			
			case TEST_MORE_THAN:
				if(val_u>test->value_unsigned)
					result=true;
				break;
			
			case TEST_BITS_SET:
				if((val_u&test->value_unsigned)==test->value_unsigned)
					result=true;
				break;
			
			case TEST_NOT_VALUE:
				if(val_u!=test->value_unsigned)
					result=true;
				break;
		}
		val_print=val_u;
	}
			
	if(force_true)
	{
		test_make_message(data, val_print, date_str, test, message);		
		return TEST_SUCCESS;
	}
	
	if(result)
	{
		if(test->tag_invalid)
		{
			//even if the result is invalid process the message, might be useful (and even needed for option --show-invalid)
			test_make_message(data, val_print, date_str, test, message);
			return TEST_INVALID;
		}
		else
		{
			test_make_message(data, val_print, date_str, test, message);
			return TEST_SUCCESS;
		}
	}
	else
		return TEST_FAILURE;
}

static void search_magic(uint8_t const * const data, const uint_fast32_t startpos, const uint_fast32_t blocksize, const bool show_invalid, bool * const success)
{
	uint_fast32_t ind_magic;
	uint_fast8_t ind_tests, old_ind_tests;
	uint_fast8_t current_level;
	bool level_down;
	bool is_invalid;
	char message[1024]; //1kB should be enough i guess
	
	for(ind_magic=0; ind_magic<NB_ENTRIES_MAGIC; ind_magic++)
	{
		bool once_succeeded[NB_LEVELS_MAX]={0};
		
		current_level=0;
		level_down=false;
		is_invalid=false;
		message[0]='\0';
		
		//this block was a pain to get right and might benefit from some cleanup...
		for(ind_tests=0; ind_tests<magic[ind_magic].nb_tests; )
		{
			current_level=magic[ind_magic].tests[ind_tests].level;
			testresult_t res=make_test(data, &magic[ind_magic].tests[ind_tests], blocksize, message);
			if(res==TEST_INVALID)
			{
				is_invalid=true;
				break;
			}
			else if(res==TEST_SUCCESS)
			{
				once_succeeded[current_level]=true;
				
				//check if next test in database has the same or a higher level
				ind_tests++;
				if(ind_tests<magic[ind_magic].nb_tests && magic[ind_magic].tests[ind_tests].level>=current_level)
					continue; //if so execute test
				else if(current_level>0)
					level_down=true; //next test is lower level -> going down one level
				else
					break; //we are at level 0 and there is no other test with same or higher level -> stop
			}
			if(res==TEST_FAILURE || level_down)
			{
				if(current_level>0 && once_succeeded[current_level-1])
				{
					old_ind_tests=ind_tests;
					if(res==TEST_FAILURE)
					{
						//failure but success at last level, continue on same level if there are more tests
						do
						{
							ind_tests++;
						} while(ind_tests<magic[ind_magic].nb_tests && magic[ind_magic].tests[ind_tests].level>current_level);
					}
					
					//check if no other test on same level found
					if(ind_tests==magic[ind_magic].nb_tests)
					{
						//go one level down
						ind_tests=old_ind_tests;
						do
						{
							ind_tests++;
						} while(ind_tests<magic[ind_magic].nb_tests && magic[ind_magic].tests[ind_tests].level!=(current_level-1));
					}
				}
				else
					break; //stop
			}
		}
		
		if(!is_invalid && strlen(message))
		{
			(*success)=true;
			printf("0x%lx (%lu):%s\n", startpos, startpos, message);
		}
		else if(is_invalid && show_invalid && strlen(message))
			printf("[INVALID]: 0x%lx (%lu):%s\n", startpos, startpos, message);
	}
}

static void mask_unprintable(char * const str, ssize_t len)
{
	if(len)
		len--; //don't touch terminating '\0'!
	
	while(len>=0)
	{
		if(str[len]<0x20 || str[len]>0x7E)
			str[len]='?';
		len--;
	}
}

static void do_search_string(uint8_t const * const data, const uint_fast32_t startpos, const uint_fast32_t blocksize, char const * const searchstring, const bool match_entire_word, bool * const success)
{
	size_t len=strlen(searchstring)+(match_entire_word?1:0); //we can do this match_entire_word-stuff because in C the string will always be 0 terminated
	uint_fast32_t offset=0;
	uint8_t * ptr;
	uint_fast32_t found_pos;
	static uint_fast32_t last_pos=0;
	
	do //we need a loop as there can be several matches inside the block
	{
		ptr=memmem(data+offset, blocksize-offset, searchstring, len);
		
		if(ptr==NULL) //no match in entire block
			return;

		(*success)=true;
		
		found_pos=startpos+ptr-data;
		
		if(found_pos==last_pos) //don't spam user with duplicate matches
		{
			offset++;
			continue;
		}
		
		if(match_entire_word)
		{
			offset+=len;
			printf("0x%lx (%lu): stringmatch: %s\n", found_pos, found_pos, searchstring);
		}
		else
		{
			char before[NB_CHARS_BEFORE_STRMATCH+1];	
			size_t nb_chars_to_copy=NB_CHARS_BEFORE_STRMATCH;
			if(ptr+NB_CHARS_BEFORE_STRMATCH>blocksize+data)
				nb_chars_to_copy=blocksize-(ptr-data);
			memcpy(before, ptr-nb_chars_to_copy, nb_chars_to_copy);
			before[nb_chars_to_copy]='\0';
			mask_unprintable(before, nb_chars_to_copy);
			
			char after[NB_CHARS_AFTER_STRMATCH+1];	
			nb_chars_to_copy=NB_CHARS_AFTER_STRMATCH;
			if(ptr+NB_CHARS_AFTER_STRMATCH>blocksize+data)
				nb_chars_to_copy=blocksize-(ptr-data);
			memcpy(after, ptr+len, nb_chars_to_copy);
			after[nb_chars_to_copy]='\0';
			mask_unprintable(after, nb_chars_to_copy);
			
			offset+=len+NB_CHARS_BEFORE_STRMATCH+NB_CHARS_AFTER_STRMATCH;

			printf("0x%lx (%lu): stringmatch: %s%s%s\n", found_pos, found_pos, before, searchstring, after);
		}
		
		last_pos=found_pos;
		
	} while(offset<blocksize);
}

static void print_usage_and_exit(void)
{
	printf("usage: fsfuzz [options]\n\n");
	printf("options:\n\t--file $name to specify input file to be examinated (MANDATORY)\n\t--blocksize $size to specify blocksize (default 2048)\n\t--nosearch to disable filesystem search\n\t--show-invalid to show invalid results (warning: output can be huge)\n\t--string \"$string\" to search for string in decrypted blocks\n\t--match-word if $string must be 0-terminated\n\n");
	printf("caution: --string may miss stuff if blocksize is too small, but the bigger the blocksize the slower the program...\n");
	exit(0);
}

int main(int argc, char * argv[])
{
	const struct option optiontable[]=
	{
		{ "file",				required_argument,	NULL,	0 },
		{ "blocksize",	 		required_argument,	NULL,	1 },
		{ "nosearch",	 		no_argument,		NULL,	2 },
		{ "show-invalid",		no_argument,		NULL, 	3 },
		{ "string",	 			required_argument,	NULL,	4 },
		{ "match-word",			no_argument,		NULL,	5 }, //TODO find better name
		
		{ "version",			no_argument,		NULL, 	100 },
		{ "help",				no_argument,		NULL, 	101 },
		{ "usage",				no_argument,		NULL, 	101 },
		
		{ NULL, 0, NULL, 0 }
	};

	int optionindex;
	int opt;
	
	char filename[SZ_FILENAME_MAX+1];
	bool file_specified=false;
	uint_fast32_t blocksize=2048;
	bool dont_do_search=false;
	bool show_invalid=false;
	char searchstring[SZ_SEARCHSTRING_MAX+1];
	bool searchstring_specified=false;
	bool match_entire_word=false;
	bool only_print_version=false;
	
	printf("This is fsfuzz version 0.1 by kittennbfive - https://github.com/kittennbfive/\n");
	printf("This tool is provided under AGPLv3+ and WITHOUT ANY WARRANTY!\n\n");
	
	while((opt=getopt_long(argc, argv, "", optiontable, &optionindex))!=-1)
	{
		switch(opt)
		{
			case '?': print_usage_and_exit(); break;
			
			case 0: strncpy(filename, optarg, SZ_FILENAME_MAX); filename[SZ_FILENAME_MAX]='\0'; file_specified=true; break;
			case 1: blocksize=atoi(optarg); break;
			case 2: dont_do_search=true; break;
			case 3: show_invalid=true; break;
			case 4: strncpy(searchstring, optarg, SZ_SEARCHSTRING_MAX); searchstring[SZ_SEARCHSTRING_MAX]='\0'; searchstring_specified=true; break;
			case 5: match_entire_word=true; break;
			
			case 100: only_print_version=true; break;
			case 101: print_usage_and_exit(); break;
			
			default: errx(1, "don't know how to handle value %d returned by getopt_long - this is a bug", opt); break;
		}
	}
	
	if(only_print_version)
		return 0;
	
	if(!file_specified)
		errx(1, "--file is missing but mandatory (try --help)");
	
	if(blocksize<128)
		errx(1, "blocksize is NaN or too small");
	
	if(searchstring_specified && strlen(searchstring)<2)
		errx(1, "string for option --string is too short");
	
	FILE * inp=fopen(filename,"rb");
	if(!inp)
		err(1, "can't open \"%s\"", filename);
	if(fseek(inp, 0, SEEK_END))
		err(1, "fseek to end of \"%s\" failed", filename);
	size_t fsize=ftell(inp);
	if(fseek(inp, 0, SEEK_SET))
	err(1, "fseek to beginning of \"%s\" failed", filename);
	printf("size of \"%s\" is %lu bytes\n\n", filename, fsize);
	uint8_t * data=malloc(fsize*sizeof(uint8_t));
	if(data==NULL)
		err(1, "malloc for \"%s\" failed", filename);
	if(fread(data, fsize, 1, inp)!=1)
		err(1, "fread for \"%s\" failed", filename);
	fclose(inp);
	
	user_decrypt_init(blocksize);
	
	uint8_t * data_current_try=malloc(blocksize*sizeof(uint8_t));
	if(data_current_try==NULL)
		err(1, "malloc for data_current_try failed");
	
	printf("starting search with blocksize %lu...\n\n", blocksize);
	
	uint_fast32_t startpos;
	bool success=false;
	
	for(startpos=0; (startpos+blocksize)<fsize; startpos++)
	{
		memcpy(data_current_try, &data[startpos], blocksize);
		
		user_decrypt_block(data_current_try, blocksize);
		
		if(searchstring_specified)
			do_search_string(data_current_try, startpos, blocksize, searchstring, match_entire_word, &success);
		
		if(!dont_do_search)
			search_magic(data_current_try, startpos, blocksize, show_invalid, &success);
	}
	
	if(!success)
		printf("nothing found - you may want to try with bigger blocksize\n");
	
	free(data);
	free(data_current_try);
	
	user_decrypt_cleanup();
	
	printf("\nall done - bye\n\n");
	
	return 0;
}
