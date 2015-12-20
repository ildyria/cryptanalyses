#include "easy1.h"

uint8 Easy1::apply_sbox(uint8 index) {
	return sbox[index];
}
uint8 Easy1::unapply_sbox(uint8 index) {
	return inv_sbox[index];
}

uint64 Easy1::apply_pbox(uint64 input) {
	uint64 output = 0;
	uint64 mask = 1;

	for (int i = 0; i < 36; ++i)
	{
		if((input & mask) > 0)
		{
			output = output | (static_cast<uint64>(1) << pbox[i]);
		}
		mask <<= 1;
	}
	return output;
}
uint64 Easy1::unapply_pbox(uint64 input) {
	uint64 output = 0;
	uint64 mask = 1;

	for (int i = 0; i < 36; ++i)
	{
		if((input & mask) > 0)
		{
			output = output | (static_cast<uint64>(1) << inv_pbox[i]);
		}
		mask <<= 1;
	}
	return output;
}

void Easy1::split(uint64 input, uint8* output) {
	if(verbose) {
		uint64 mask = 1;
		mask <<= 35;
		for (int i = 0; i < 36; ++i)
		{
			if((i % 6 == 0) && (i > 0)) printf("|");
			printf("%li", (mask & input) >> (35 - i));
			mask >>= 1;
		}
		printf("\n");
	}

	// ACTUAL FUNCTION...
	for (int i = 0; i < 6; ++i)
	{
		output[i] = (input >> (i*6)) & 0x3f;
	}

	if(verbose) {
		uint8 mask = 1;
		for (int i = 0; i < 6; ++i)
		{
			if(i > 0) printf("|");
			mask = 1;
			mask <<= 5;
			for (int j = 0; j < 6; ++j)
			{
				printf("%i", (mask & output[5-i]) >> (5 - j));
				mask >>= 1;
			}
		}
		printf("\n");
	}
}

uint64 Easy1::join(uint8* input) {
	uint64 output = 0;

	if(verbose) {
		uint8 mask = 1;
		for (int i = 0; i < 6; ++i)
		{
			if(i > 0) printf("|");
			mask = 1;
			mask <<= 5;
			for (int j = 0; j < 6; ++j)
			{
				printf("%i", (mask & input[5-i]) >> (5 - j));
				mask >>= 1;
			}
		}
		printf("\n");
	}

	for (int i = 0; i < 6; ++i)
	{
		output <<= 6;
		output = (output | (input[5-i] & 0x3f));
	}

	if(verbose) {
		uint64 mask2 = 1;
		mask2 <<= 35;
		for (int i = 0; i < 36; ++i)
		{
			if((i % 6 == 0) && (i > 0)) printf("|");
			printf("%li", (mask2 & output) >> (35 - i));
			mask2 >>= 1;
		}
		printf("\n");
	}
	return output;
}

uint64 Easy1::apply_key(uint64 input)
{
	// key is 18 bits
	return (input ^ _key);
}

uint64 Easy1::round(uint64 input)
{
	if(verbose) printf("------------------\n");
	if(verbose) printf("input : ");
	if(verbose) print(input);
	uint8 tab[6] = {0,0,0,0,0,0};

	split(input,tab);
	for (int i = 0; i < 6; ++i)
	{
		tab[i] = apply_sbox(tab[i]);
	}
	input = join(tab);
	if(verbose) printf("sbox  : ");
	if(verbose) print(input);

	// input = apply_pbox(input);
	if(verbose) printf("pbox  : ");
	if(verbose) print(input);
	
	input = apply_key(input);
	if(verbose) printf("key   : ");
	if(verbose) print(input);
	
	if(verbose) printf("------------------\n");
	return input;
}


uint64 Easy1::unround(uint64 input)
{
	if(verbose) printf("------------------\n");
	if(verbose) printf("input : ");
	if(verbose) print(input);

	input = apply_key(input);
	if(verbose) printf("-key  : ");
	if(verbose) print(input);

	// input = unapply_pbox(input);
	if(verbose) printf("-pbox : ");
	if(verbose) print(input);

	uint8 tab[6] = {0,0,0,0,0,0};
	split(input,tab);
	for (int i = 0; i < 6; ++i)
	{
		tab[i] = unapply_sbox(tab[i]);
	}
	input = join(tab);
	if(verbose) printf("-sbox : ");
	if(verbose) print(input);
	
	if(verbose) printf("------------------\n");
	return input;
}


uint64 Easy1::encrypt(uint64 input) {
	for (uint i = 0; i < _rounds; ++i)
	{
		input = round(input);
	}
	return input;
}

uint64 Easy1::decrypt(uint64 input) {
	for (uint i = 0; i < _rounds; ++i)
	{
		input = unround(input);
	}
	return input;
}


void Easy1::print_boxes(){
	printf("pbox\n");
	for(uint i = 0; i < 36; ++i)
	{
		printf("%4u   => %4u   => %4u   \n",i,pbox[i],inv_pbox[pbox[i]]);
	}
	printf("sbox\n");
	for(uint i = 0; i < 64; ++i)
	{
		printf("%4u   => %4u   => %4u   \n",i,sbox[i],inv_sbox[sbox[i]]);
	}
}

void Easy1::print(uint64 input)
{
	uint64 mask = 1;
	mask <<= 35;
	for (int i = 0; i < 36; ++i)
	{
		printf("%li", (mask & input) >> (35 - i));
		mask >>= 1;
	}
	printf("\n");
}

