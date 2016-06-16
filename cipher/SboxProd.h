#pragma once
#include "../includes/typedef.h"
#include "../includes/cipher.h"
#include "../tools/crypto_tools.h"

class SboxProd : public Cipher
{

public:

	SboxProd() : Cipher(0,0) {};

	virtual ~SboxProd(){};

	virtual void print(uint64 b) {
		Crypto_tools::printn<64>(b);
	};

	virtual void test(){};

	virtual uint8 apply_s(uint16 input, int slice) {
		uint16 mask = 1;
		for (int i = 1; i < slice; ++i)
		{
			mask |= mask << 1;
		}
		uint32 res = input & mask;
		res = res * res;
		res = (res >> slice) ^ (res & mask);
		return res & mask;
	};

};
