#pragma once
#include "../includes/typedef.h"

class Crypto_tools
{
public:
	// Crypto_primitives();
	// ~Crypto_primitives();

	template<typename I, typename O, int blockSize, int blockNum, O mask> static void split(I input, O* output)
	{
		// if(verbose) {
		// 	uint64 mask = 1;
		// 	mask <<= 35;
		// 	for (int i = 0; i < 36; ++i)
		// 	{
		// 		if((i % 6 == 0) && (i > 0)) printf("|");
		// 		printf("%li", (mask & input) >> (35 - i));
		// 		mask >>= 1;
		// 	}
		// 	printf("\n");
		// }

		// ACTUAL FUNCTION...
		for (int i = 0; i < blockNum; ++i)
		{
			output[i] = (input >> (i*blockSize)) & mask;
		}

		// if(verbose) {
		// 	uint8 mask = 1;
		// 	for (int i = 0; i < 6; ++i)
		// 	{
		// 		if(i > 0) printf("|");
		// 		mask = 1;
		// 		mask <<= 5;
		// 		for (int j = 0; j < 6; ++j)
		// 		{
		// 			printf("%i", (mask & output[5-i]) >> (5 - j));
		// 			mask >>= 1;
		// 		}
		// 	}
		// 	printf("\n");
		// }
	}

	template<typename I, typename O, int blockSize, int blockNum, O mask> static O join(I* input)
	{
		O output = 0;

		// if(verbose) {
		// 	for (int i = 0; i < 6; ++i)
		// 	{
		// 		if(i > 0) printf("|");
		// 		Crypto_tools::print<6>(input[5-i]);
		// 	}
		// 	printf("\n");
		// }

		for (int i = 1; i <= blockNum; ++i)
		{
			output <<= blockSize;
			output = (output | (input[blockNum -i] & mask));
		}

		// if(verbose) {
		// 	uint64 mask2 = 1;
		// 	mask2 <<= 35;
		// 	for (int i = 0; i < 36; ++i)
		// 	{
		// 		if((i % 6 == 0) && (i > 0)) printf("|");
		// 		printf("%li", (mask2 & output) >> (35 - i));
		// 		mask2 >>= 1;
		// 	}
		// 	printf("\n");
		// }
		return output;
	}

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