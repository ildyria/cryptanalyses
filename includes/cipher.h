#pragma once
#include <iostream>
#include <stdio.h>
#include "../includes/typedef.h"

class Cipher
{
public:
	Cipher(){};
	virtual ~Cipher(){};

	virtual uint64 encrypt(uint64 b)
	{
		return b;
	};

	virtual void print(uint64 b)
	{
		uint64 mask = 1;
		mask <<= 63;
		for (int i = 0; i < 64; ++i)
		{
			printf("%li", (mask & b) >> (63 - i));
			mask >>= 1;
		}
	};
};