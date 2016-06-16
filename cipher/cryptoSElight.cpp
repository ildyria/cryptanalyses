#include "cryptoSElight.h"

uint8 cryptoSElight::apply_sbox(uint8 index) {
	return sbox[index];
}
uint8 cryptoSElight::unapply_sbox(uint8 index) {
	return inv_sbox[index];
}

uint64 cryptoSElight::apply_key(uint64 input)
{
	// key is 18 bits
	return (input ^ _key);
}

uint64 cryptoSElight::round(uint64 input)
{
	input = input & 0xffffffff;
	if(verbose) printf("------------------\n");
	if(verbose) printf("input : ");
	if(verbose) Crypto_tools::printn<32>(input);
	uint8 tab[8] = {0,0,0,0,0,0,0,0};

	input = apply_key(input);
	if(verbose) printf("key   : ");
	if(verbose) Crypto_tools::printn<32>(input);

	Crypto_tools::split<uint64,uint8,4,8,0xf>(input,tab);
	for (int i = 0; i < 8; ++i)
	{
		tab[i] = apply_sbox(tab[i]);
	}
	input = Crypto_tools::join<uint8,uint64,4,8,0xf>(tab);
	if(verbose) printf("sbox  : ");
	if(verbose) Crypto_tools::printn<32>(input);

	input = Crypto_tools::rotR<uint64,2,32,0xffffffff>(input);
	if(verbose) printf("pbox  : ");
	if(verbose) Crypto_tools::printn<32>(input);
	
	if(verbose) printf("------------------\n");
	return input;
}


uint64 cryptoSElight::unround(uint64 input)
{
	input = input & 0xffffffff;
	if(verbose) printf("------------------\n");
	if(verbose) printf("input : ");
	if(verbose) Crypto_tools::printn<32>(input);

	input = Crypto_tools::rot<uint64,2,32,0xffffffff>(input);
	if(verbose) printf("-pbox : ");
	if(verbose) Crypto_tools::printn<32>(input);

	uint8 tab[8] = {0,0,0,0,0,0,0,0};
	Crypto_tools::split<uint64,uint8,4,8,0xf>(input,tab);
	for (int i = 0; i < 8; ++i)
	{
		tab[i] = unapply_sbox(tab[i]);
	}
	input = Crypto_tools::join<uint8,uint64,4,8,0xf>(tab);
	if(verbose) printf("-sbox : ");
	if(verbose) Crypto_tools::printn<32>(input);
	
	input = apply_key(input);
	if(verbose) printf("-key  : ");
	if(verbose) Crypto_tools::printn<32>(input);

	if(verbose) printf("------------------\n");
	return input;
}


uint64 cryptoSElight::encrypt(uint64 input) {
	input = input & 0xffffffff;
	for (uint i = 0; i < _rounds; ++i)
	{
		input = round(input);
	}
	return input;
}

uint64 cryptoSElight::decrypt(uint64 input) {
	input = input & 0xffffffff;
	for (uint i = 0; i < _rounds; ++i)
	{
		input = unround(input);
	}
	return input;
}


void cryptoSElight::print_boxes(){
/*	printf("pbox\n");
	for(uint i = 0; i < 32; ++i)
	{
		printf("%4u   => %4u   => %4u   \n",i,pbox[i],inv_pbox[pbox[i]]);
	}
*/	printf("sbox\n");
	for(uint i = 0; i < 16; ++i)
	{
		printf("%4u   => %4u   => %4u   \n",i,sbox[i],inv_sbox[sbox[i]]);
	}
}

void cryptoSElight::print(uint64 input)
{
	Crypto_tools::printn<32>(input);
}

void cryptoSElight::test(){
	uint64 toencrypt = 1;
	for (int i = 0; i < 32; ++i)
	{
		printf("%i\n",i);
		Crypto_tools::printn<32>(toencrypt);
		auto temp = encrypt(toencrypt);
		Crypto_tools::printn<32>(temp);
		temp = decrypt(temp);
		Crypto_tools::printn<32>(temp);
		printf("====================\n");

		toencrypt <<= 1;
	}

	printf("########################\n");

	print_boxes();
}


uint64  cryptoSElight::unround1(uint64 input, uint64 k)
{
	input = input & 0xffffffff;
	if(verbose) printf("------------------\n");
	if(verbose) printf("input : ");
	if(verbose) Crypto_tools::printn<32>(input);

	input = Crypto_tools::rot<uint64,2,32,0xffffffff>(input);
	if(verbose) printf("-pbox : ");
	if(verbose) Crypto_tools::printn<32>(input);

	uint8 tab[8] = {0,0,0,0,0,0,0,0};
	Crypto_tools::split<uint64,uint8,4,8,0xf>(input,tab);
	for (int i = 0; i < 8; ++i)
	{
		tab[i] = unapply_sbox(tab[i]);
	}
	input = Crypto_tools::join<uint8,uint64,4,8,0xf>(tab);
	if(verbose) printf("-sbox : ");
	if(verbose) Crypto_tools::printn<32>(input);
	
	input = input ^ k;
	if(verbose) printf("-key  : ");
	if(verbose) Crypto_tools::printn<32>(input);

	if(verbose) printf("------------------\n");
	return input;
}
