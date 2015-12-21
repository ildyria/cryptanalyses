#pragma once
#include <iostream>
#include <stdio.h>
#include "../includes/typedef.h"
#include "../tools/crypto_tools.h"

class Cipher
{

protected:
	uint64 _key;
	uint _rounds;
	bool verbose = false;

public:

	Cipher(uint64 key, int rounds) : _key(key), _rounds(rounds) {};

	virtual ~Cipher(){};

	virtual uint64 encrypt(uint64 b)
	{
		return b;
	};

	virtual uint64 decrypt(uint64 b)
	{
		return b;
	};

	virtual void print(uint64 b) {
		Crypto_tools::printn<64>(b);
	};

	virtual void test(){};

};
