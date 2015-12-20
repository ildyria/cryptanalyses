#pragma once
#include "../includes/typedef.h"

class Crypto_tools
{
public:
	// Crypto_primitives();
	// ~Crypto_primitives();

	template<typename U> static void inv_box(U* in, U* out, int num)
	{
		for (int i = 0; i < num; ++i)
		{
			out[in[i]] = i;
		}
	}

	template<typename U> static U rot2(U input)
	{
		U output = (input << 2) & 0xff;
		output |= input >> (sizeof(U) - 2);
		return output;
	}

	template<int N> static void print(uint64 input)
	{
		uint64 mask = 1;
		mask <<= (N - 1);
		for (int i = 1; i <= N; ++i)
		{
			printf("%li", (mask & input) >> (N - i));
			mask >>= 1;
		}
	}

	template<int N> static void printn(uint64 input)
	{
		uint64 mask = 1;
		mask <<= (N - 1);
		for (int i = 1; i <= N; ++i)
		{
			printf("%li", (mask & input) >> (N - i));
			mask >>= 1;
		}
		printf("\n");
	}

};