#pragma once
#include <stdio.h>
#include <iostream>   // std::cout
#include <string>     // std::string, std::stoi
#include <cstdlib> 

int read_args(int& argc, char const* argv[])
{
	int i = 1;

	if (argc == 2)
	{
		i = strtol(argv[1],0,10);
		printf("cipher chosen : ");
	}
	else
	{
		printf("cipher by default : ");
	}

	return i;
}