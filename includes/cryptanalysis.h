#pragma once
#include <iostream>
#include <stdio.h>
#include "../tools/random.h"
#include "../includes/typedef.h"
#include "../tools/crypto_tools.h"

class Cryptanalysis
{

public:

	Cryptanalysis() {};
	virtual ~Cryptanalysis(){};

	virtual void generateTable() = 0;

	virtual void printTable(bool zeroes = false) = 0;

	virtual void sort(bool print = false) = 0;

	virtual void attack() = 0;
};
