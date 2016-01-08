#pragma once
#include <iostream>
#include <stdio.h>
#include "../includes/typedef.h"
#include "../tools/crypto_tools.h"

class Cryptanalysis
{

public:

	Cryptanalysis() {};
	virtual ~Cryptanalysis(){};

	virtual void generateTable() = 0;

	virtual void analysis(bool zeroes = false) = 0;

	virtual void sort() = 0;

};
