#include "feal.h"

uint32 Feal::roundf(uint32 alpha, uint32 beta){
	uint8 alphatab[4] = {0,0,0,0};
	uint8 betatab[4] = {0,0,0,0};

	Crypto_tools::split<uint64,uint8,8,4,0xff>(alpha,alphatab);
	Crypto_tools::split<uint64,uint8,8,4,0xff>(beta,betatab);

	uint8 fs[4] = {0,0,0,0};

	fs[1] = alphatab[1] ^ betatab[0] ^ alphatab[0];
	fs[2] = alphatab[2] ^ betatab[1] ^ alphatab[3];
	fs[1] = sbox(fs[1], fs[2], 1);
	fs[2] = sbox(fs[2], fs[1], 0);
	fs[0] = sbox(alphatab[0], fs[1], 0);
	fs[3] = sbox(alphatab[3], fs[2], 1);

	return Crypto_tools::join<uint8,uint64,8,4,0x3f>(fs);
}

pair<uint32,uint32>* Feal::round(pair<uint32,uint32>* input){
	return input;
}

pair<uint32,uint32>* Feal::unround(pair<uint32,uint32>* input){
	return input;
}


uint64 Feal::encrypt(uint64 input) {
	for (uint i = 0; i < _rounds; ++i)
	{
		// input = round(input);
	}
	return input;
}

uint64 Feal::decrypt(uint64 input) {
	for (uint i = 0; i < _rounds; ++i)
	{
		// input = unround(input);
	}
	return input;
}

void Feal::print(uint64 input)
{
	Crypto_tools::printn<36>(input);
}

void Feal::test(){
	uint64 toencrypt = 1;
	for (int i = 0; i < 36; ++i)
	{
		printf("%i\n",i);
		Crypto_tools::printn<36>(toencrypt);
		auto temp = encrypt(toencrypt);
		Crypto_tools::printn<36>(temp);
		temp = decrypt(temp);
		Crypto_tools::printn<36>(temp);
		printf("====================\n");

		toencrypt <<= 1;
	}

	printf("########################\n");

}
