#include "easy1.h"

uint8 Easy1::apply_sbox(uint8 index) {
	return sbox[index];
}

uint64 Easy1::apply_pbox(uint64 input) {
	uint64 output = 0;
	uint64 mask = 1;

	for (int i = 0; i < 36; ++i)
	{
		if((input & mask) > 0)
		{
			output = output | (1 << pbox[i]);
		}
		mask <<= 1;
	}
	return output;
}

void Easy1::split(uint64 input, uint8* output) {
	for (int i = 0; i < 6; ++i)
	{
		output[i] = (input >> (i*6)) & 0x3f;
	}
}

uint64 Easy1::join(uint8* input) {
	uint64 output = 0;
	for (int i = 0; i < 6; ++i)
	{
		output = output | (input[i] << (i*6));
	}
	return output;
}

uint64 Easy1::round(uint64 input)
{
	uint8 tab[6] = {0,0,0,0,0,0};

	split(input,tab);
	for (int i = 0; i < 6; ++i)
	{
		tab[i] = apply_sbox(tab[i]);
	}
	return apply_pbox(join(tab));
}

uint64 Easy1::encrypt(uint64 input) {
	return round(input);
}

void Easy1::print(uint64 b)
{
	uint64 mask = 1;
	mask <<= 35;
	for (int i = 0; i < 36; ++i)
	{
		printf("%li", (mask & b) >> (35 - i));
		mask >>= 1;
	}
}
