#pragma once
#include <iostream>
#include <stdio.h>
#include "../includes/typedef.h"

class Cipher
{
public:
	Cipher(){};
	virtual ~Cipher(){};

	virtual uint64 execute(uint64 b)
	{
		return b;
	};
};