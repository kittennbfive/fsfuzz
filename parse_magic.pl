#! /usr/bin/env perl
use strict;
use warnings FATAL=>'all';
use autodie;

=pod
This is a helper for fsfuzz, a tool to find individually obfuscated or encrypted filesystems in firmware dumps.

This script will parse the file "filesystems" (stolen from binwalk(*) and modified/extended, licence MIT) and create the needed data-structures for fsfuzz.

You only need this script if you modify the file "filesystems".

Caution, only a subset of the grammar of `man 5 magic` (extended by the binwalk-developpers) is supported.

(c) 2023 by kittennbfive 

https://github.com/kittennbfive

provided under AGPLv3+ and WITHOUT ANY WARRANTY!

Please read the fine manual.

(*) https://github.com/ReFirmLabs/binwalk/blob/master/src/binwalk/magic/filesystems
=cut

my $verbose=0; #only useful for debugging

my $l;
my ($level, $offset, $type, $test, $message, @tags);
my @tests;
my $nb_tests_max=0;
my $nb_levels_max=0;
my $nb_bytes_max=0;
my @magic;

print "Helper script for fsfuzz - (c) 2023 by kittennbfive - AGPLv3+ and NO WARRANTY!\n\n";

print "start...\n";

open my $inp, '<', 'filesystems';
while(($l=<$inp>))
{
	chomp($l);
	
	next if($l=~/^#/);
	
	if($l=~/^\s*$/)
	{
		next if(scalar(@tests)==0);
		
		$nb_tests_max=scalar(@tests) if(scalar(@tests)>$nb_tests_max);
		
		push @magic, [@tests];
		$#tests=-1;
	}
	elsif($l=~/^
		(?<level>>{0,})
		(?<offset>(?:\d+|0x[[:xdigit:]]+)(?:[+-](?:\d+|0x[[:xdigit:]]+))?)\s+
		(?<type>u?(?:byte|short|long|quad|beshort|belong|bequad|leshort|lelong|lequad|string|bedate|ledate)(?:[&*](\d+|0x[[:xdigit:]]+))?)\s+
		(?<test>
			(??{if($+{type} eq 'string')
					{'!?(?:[\\d\\w\-!]|\\\x[[:xdigit:]]{2}|\\\0\d{2})+'}
				else
					{'(?:[=<>&!]?(?:0x[[:xdigit:]]+|\\d+))|x'}})
		)\s{0,}
		(?<message>.*)
	$/x)
	{
		($level, $offset, $type, $test, $message)=(length($+{level}), $+{offset}, $+{type}, $+{test}, $+{message});
		push @tags, $1 while($message=~s/{(.+?)}//g);
		push @tests, {'level'=>$level, 'offset'=>$offset, 'type'=>$type, 'test'=>$test, 'message'=>$message, 'tags'=>[@tags]};
		$nb_levels_max=$level if($level>$nb_levels_max);
		$nb_bytes_max=get_nb_bytes_test($test) if(get_nb_bytes_test($test)>$nb_bytes_max);

		if($verbose)
		{
			print "level:$level  offset:$offset  type:$type  test:$test  message:$message  ";
			print "tags:",join(',', @tags) if(scalar(@tags)); #tag "invalid" used by fsfuzz, all others ignored
			print "\n";
		}

		$#tags=-1;
	}
	else
	{
		die "no match for line \"$l\"";
	}
}
close $inp;

print "file parsed, writing output...\n";

open my $outp, '>', 'magicdata_constants.h';
print $outp "//AUTOGENERATED ON ".localtime()." - DO NOT EDIT\n";
print $outp "#ifndef __MAGICDATA_CONSTANTS_H__\n#define __MAGICDATA_CONSTANTS_H__\n\n";
print $outp <<END1;
/*
This file is part of fsfuzz.

(c) 2023 by kittennbfive

https://github.com/kittennbfive

AGPLv3+ and NO WARRANTY!
*/

END1
print $outp "#define NB_ENTRIES_MAGIC ",scalar(@magic),"\n";
print $outp "#define NB_TESTS_MAX $nb_tests_max\n";
print $outp "#define NB_LEVELS_MAX $nb_levels_max\n";
print $outp "#define NB_BYTES_MAX $nb_bytes_max\n\n";
print $outp "#endif\n";
close $outp;


open $outp, '>', 'magicdata.c';
print $outp "//AUTOGENERATED ON ".localtime()." - DO NOT EDIT\n";
print $outp <<END2;
#define FILE_MAGICDATA_C
#include <stdint.h>
#include <stdbool.h>

#include "magicdata.h"

/*
This file is part of fsfuzz.

(c) 2023 by kittennbfive

https://github.com/kittennbfive

AGPLv3+ and NO WARRANTY!
*/

END2
print $outp "const magic_t magic[NB_ENTRIES_MAGIC]={\n";
foreach my $m (@magic)
{
	print $outp "\t{ ",scalar(@{$m}),",\n\t\t{\n";
	foreach my $t (@{$m})
	{
		print $outp make_test($t);
	}
	print $outp "\t\t}\n\t},\n";
}
print $outp "};\n";
close $outp;

print "all done\n";

### subs ###

sub get_nb_bytes_test
{
	my $test=shift;
	
	$test=~s/^([<>&!])//;
	if($test!~/^(0x[[:xdigit:]]+|\d+)/)
	{
		$test=~s/\\x([[:xdigit:]]{2})/chr(oct('0x'.$1))/ge;
		return scalar(split(//, $test));
	}
	
	return 0; #not a byte array
}


sub make_test
{
	my $ref=shift;
	my $ret="\t\t\t{ ";
	
	my %data_types=('string'=>'DATA_STRING', 'date'=>'DATA_DATE', 'udate'=>'DATA_UDATE', 'byte'=>'DATA_INT8', 'ubyte'=>'DATA_UINT8', 'short'=>'DATA_INT16', 'ushort'=>'DATA_UINT16', 'long'=>'DATA_INT32', 'ulong'=>'DATA_UINT32', 'quad'=>'DATA_INT64', 'uquad'=>'DATA_UINT64');
	my %test_types=('<'=>'TEST_LESS_THAN', '>'=>'TEST_MORE_THAN', '&'=>'TEST_BITS_SET', '!'=>'TEST_NOT_VALUE');
	
	my $type=$ref->{'type'};
	my $endian='ENDIAN_UNDEF';
	my $is_unsigned=0;
	my $op_on_value='DATAOP_NONE';
	my $op_operand=0;
	my $test=$ref->{'test'};
	
	
	$is_unsigned=1 if($type=~s/^u//);
	
	if($type=~s/^le//)
	{
		$endian='ENDIAN_LE';
	}
	elsif($type=~s/^be//)
	{
		$endian='ENDIAN_BE';
	}
	
	$type='u'.$type if($is_unsigned);
	
	if($type=~s/&(0x[[:xdigit:]]+|\d+)$//)
	{
		$op_on_value='DATAOP_AND';
		$op_operand=$1;
	}
	elsif($type=~s/\*(0x[[:xdigit:]]+|\d+)$//)
	{
		$op_on_value='DATAOP_MULTIPLY';
		$op_operand=$1;
	}
	
	my $test_type='TEST_EQUAL';
	my $test_type_value='value_unsigned';
	#for numeric value
	my $test_value=0;
	#for string/bytes
	my @test_bytes;

	if($test eq 'x')
	{
		$test_type='TEST_TRUE';
	}
	else
	{
		if($test=~s/^([<>&!])//)
		{
			$test_type=$test_types{$1};
		}
		
		if($test=~/^(0x[[:xdigit:]]+|\d+)/)
		{
			$test_value=$1;
			$test_type_value=$is_unsigned?'value_unsigned':'value_signed';
		}
		else
		{
			$test=~s/\\x([[:xdigit:]]{2})/chr(oct('0x'.$1))/ge;
			$test_type_value='string';
			@test_bytes=map { $_=sprintf('0x%02x', ord($_)) } split(//, $test);
		}
	}
	
	my $test_details;
	if($test_type_value eq 'string')
	{
		$test_details='.string={ '.scalar(@test_bytes).', {'.join(', ', @test_bytes).'} }';
	}
	else
	{
		$test_details='.'.$test_type_value.'='.$test_value;
	}
	
	my $tag_invalid='false';
	foreach (@{$ref->{'tags'}})
	{
		$tag_invalid='true' if($_ eq 'invalid');
	}
	
	my $msg=$ref->{'message'};
	
	my $flag_no_space='false';
	$flag_no_space='true' if($msg=~s/^\\b//);
	
	$msg=~s/"/\\"/g;
	$msg=~s/(%\.?\d*)([dxXu])/$1l$2/; #argument is always 64 bit in C-code -> add 'l' to format specifier if not already there - yes it's an ugly hack...
	
	my $msg_nb_args=scalar($msg=~/%[^%]/);
	die "more than one argument in message" if($msg_nb_args>1);
	
	$ret.=$ref->{'level'}.', '.make_math($ref->{'offset'}).', '.$data_types{$type}.', '.$endian.', '.$op_on_value.', '.$op_operand.', '.$test_type.', '.$test_details.', '.$tag_invalid.', '.$flag_no_space.', '.($msg_nb_args?'true':'false').', "'.$msg.'" },'."\n";
	
	return $ret;
}

sub make_math #eval() should work too but is somewhat insecure
{
	my $expr=shift;
	my $result=$expr;
	
	$result=~s/(0x[[:xdigit:]]+)/oct($1)/ge;
	
	if($result=~/[()]/)
	{
		die "make_math: parenthesis are unsupported for now";
	}
	
	while($result=~/[*\/]/)
	{
		$result=~s/(\d+)\*(\d+)/$1*$2/e;
		$result=~s/(\d+)\/(\d+)/$1\/$2/e;
	}
	
	while($result=~/[+-]/)
	{
		$result=~s/(\d+)\+(\d+)/$1+$2/e;
		$result=~s/(\d+)-(\d+)/$1-$2/e;
	}
	
	return sprintf("0x%x", $result);
}
