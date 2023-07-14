#ifndef __MAGICATA_H__
#define __MAGICATA_H__

#include <stdint.h>
#include <stdbool.h>

#include "magicdata_constants.h"

/*
This file is part of fsfuzz.

(c) 2023 by kittennbfive

https://github.com/kittennbfive

AGPLv3+ and NO WARRANTY!
*/

typedef enum
{
	DATA_STRING,
	DATA_DATE, //32 bits signed
	DATA_UDATE, //32 bits unsigned
	DATA_INT8, //byte
	DATA_UINT8,
	DATA_INT16, //short
	DATA_UINT16,
	DATA_INT32, //long
	DATA_UINT32,
	DATA_INT64, //quad
	DATA_UINT64
} datatype_t;

typedef enum
{
	DATAOP_NONE,
	DATAOP_AND, //'&'
	DATAOP_MULTIPLY //'*'
} dataop_t;

typedef enum
{
	TEST_TRUE, //'x'
	TEST_EQUAL, //(none)
	TEST_LESS_THAN, //'<'
	TEST_MORE_THAN, //'>'
	TEST_BITS_SET, //'&'
	TEST_NOT_VALUE //'!'
} testtype_t;

typedef enum
{
	ENDIAN_UNDEF,
	ENDIAN_LE,
	ENDIAN_BE
} endian_t;

typedef struct
{
	uint_fast8_t level;
	
	uint64_t offset; //lots of stuff like relative offsets, indirect offsets, calculated offsets, ... unsupported here! 
	
	datatype_t data_type;
	
	endian_t endian;
	
	dataop_t operation_on_value;
	uint64_t operand;
	
	testtype_t test_type;
	
	union
	{
		uint64_t value_unsigned;
		int64_t value_signed;
		struct
		{
			uint_fast8_t nb_bytes;
			uint8_t bytes[NB_BYTES_MAX];
		} string;
	};
		
	bool tag_invalid;
	
	bool flag_no_space; //'\b'
	bool message_has_argument;
	char * message;
} test_t;

typedef struct
{
	uint_fast8_t nb_tests;
	test_t tests[NB_TESTS_MAX];
} magic_t;

#ifndef FILE_MAGICDATA_C
extern const magic_t magic[NB_ENTRIES_MAGIC];
#endif

#endif
