#pragma once
#include "../includes/typedef.h"
#include <climits>


class Crypto_tools
{
public:
	template<typename I, int size> static int posi(I in){
		I mask = 1;
		mask <<= (size -1);
		for (int i = 0; i < size; ++i)
		{
			if ((mask & in) > 0)
			{
				return i;
			}
			mask >>=1;
		}
		return -1;
	}	

	template<typename I, int size> static int pos(I in){
		I mask = 1;
		for (int i = 0; i < size; ++i)
		{
			if ((mask & in) > 0)
			{
				return i;
			}
			mask <<=1;
		}
		return -1;
	}	

	template<typename I, typename O, int blockSize, int blockNum, O mask> static void spliti(I input, O* output)
	{
		for (int i = 0; i < blockNum; ++i)
		{
			output[blockNum - (i+1)] = (input >> (i*blockSize)) & mask;
		}
	}

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

	template<typename I, typename O, int blockSize, int blockNum, O mask> static O joini(I* input)
	{
		O output = 0;
		for (int i = 0; i < blockNum; ++i)
		{
			output <<= blockSize;
			output = (output | (input[i] & mask));
		}
		return output;
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

	template<typename U, int num> static inline U rot(U input)
	{
		U output = (input << num);
		output |= input >> (sizeof(U)* CHAR_BIT - num);
		return output;
	}

	template<typename U, int num, int size, U mask> static inline U rot(U input)
	{
		U output = (input << num) & mask;
		output |= input >> (size - num);
		return output;
	}

	template<typename U, int num> static inline U rotR(U input)
	{
		U output = input << (sizeof(U)* CHAR_BIT - num);
		output |= (input >> num);
		return output;
	}

	template<typename U, int num, int size, U mask> static inline U rotR(U input)
	{
		U output = (input << (size - num)) & mask;
		output |= (input >> num);
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

	static void print(uint64 input, int N)
	{
		uint64 mask = 1;
		mask <<= (N - 1);
		for (int i = 1; i <= N; ++i)
		{
			printf("%li", (mask & input) >> (N - i));
			mask >>= 1;
		}
	}

	static void printn(uint64 input, int N)
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

	template<int size> static uint64 apply_pbox(uint64 input, uint8* pbox) {
		uint64 output = 0;
		uint64 mask = 1;

		for (int i = 0; i < size; ++i)
		{
			if((input & mask) > 0)
			{
				output = output | (static_cast<uint64>(1) << pbox[i]);
			}
			mask <<= 1;
		}
		return output;
	}

	template<typename In, typename Out> static Out concat(In in1, In in2)
	{
		Out output = 0;
		output |= in1;
		output <<= sizeof(In) * CHAR_BIT;
		output |= in2;
		return output;
	}

	template<typename In, typename Out, int sub> static Out concat(In in1, In in2)
	{
		Out output = 0;
		output |= in1;
		output <<= sub;
		output |= in2;
		return output;
	}

	template<typename Cipher> static void testCipher(uint64 key, int rounds, uint64 tocipher, uint64 expected) {
		if(tocipher != 0 || expected != 0)
		{
			Cipher* cipher = new Cipher(key,rounds);
			printf("to cipher : %016lx\n",tocipher);
			printf("====================\n");
			uint64 ciphered = cipher->encrypt(tocipher);
			printf("ciphered : %016lx\n",ciphered);
			printf("====================\n");
			uint64 deciphered = cipher->decrypt(ciphered);
			printf("deciphered : %016lx\n",deciphered);
			printf("====================\n");
			printf("cipher match ? %s\n",(ciphered == expected) ? "yes" : "no");
			printf("plain and decrypt match ? %s\n",(tocipher == deciphered) ? "yes" : "no");
			printf("====================\n");
		}
		else
		{
			printf("No tests\n");
		}
	}

	static int XorBits(uint64 val, int size)
	{
		int res = 0;
		for (int i = 0; i < size; ++i)
		{
			res ^= val & static_cast<uint64>(1);
			val >>= 1;
		}
		return res;
	}
};