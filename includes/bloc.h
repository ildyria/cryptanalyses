#pragma once
#include <iostream>
#include <stdio.h>
#include "../includes/typedef.h"

class Bloc
{
	uint64 size;

public:
	Bloc(){};
	virtual ~Bloc(){};

	void set();
	uint64 get();
};