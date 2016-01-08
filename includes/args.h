#pragma once
#include <stdio.h>
#include <string>     // std::string, std::stoi
#include <string.h>
#include <omp.h>
#include <cstdlib>
#include "../includes/typedef.h"

prog_options read_args(int& argc, char const* argv[])
{
	prog_options options;

	options.cryptanalysis_type = 0;		// 1
	options.cipher_type = 0;			// 1
	options.cryptanalysis_solve = 0;	// 1

	options.num_proc_to_use = 1;
	options.testing = false;

// report settings
	for (int i = 1; i < argc; i++)
	{
		if(strcmp(argv[i],"-n") == 0)
		{
			if(i + 1 < argc)
			{
				i++;
				int num_proc_to_use = 1;
				num_proc_to_use = std::max(num_proc_to_use, std::stoi(argv[i],nullptr,0));
				num_proc_to_use = num_proc_to_use > omp_get_num_procs() ? omp_get_num_procs() : num_proc_to_use ;
				printf("%i core selected over %i.\n", num_proc_to_use , omp_get_num_procs());

			 	omp_set_num_threads(num_proc_to_use);
			}
			else
			{
				printf("-n require an additionnal parameter.\n");
				exit(1);
			}
		}
		else if(strcmp(argv[i],"-a") == 0 || strcmp(argv[i],"--analysis") == 0)
		{
			if(i + 1 < argc)
			{
				i++;
				options.cryptanalysis_type = static_cast<uint8>(std::stoi(argv[i],nullptr,0));
				printf("%i : analysis chosen (0: none, 1: linear, 2: diff).\n", options.cryptanalysis_type);
			}
			else
			{
				printf("-a require an additionnal parameter.\n");
				exit(1);
			}
		}
		else if(strcmp(argv[i],"-c") == 0 || strcmp(argv[i],"--cipher") == 0)
		{
			if(i + 1 < argc)
			{
				i++;
				options.cipher_type = static_cast<uint8>(std::stoi(argv[i],nullptr,0));
				printf("%i : cipher chosen (0: Easy1, 1: FEAL-8, 2: DES).\n", options.cipher_type);
			}
			else
			{
				printf("-c require an additionnal parameter.\n");
				exit(1);
			}
		}
		else if(strcmp(argv[i],"-b") == 0 || strcmp(argv[i],"--break") == 0)
		{
			if(i + 1 < argc)
			{
				i++;
				options.cryptanalysis_solve = static_cast<uint8>(std::stoi(argv[i],nullptr,0));
				printf("%i : try to break the cipher (0: no, 1: yes).\n", options.cryptanalysis_solve);
			}
			else
			{
				printf("-b require an additionnal parameter.\n");
				exit(1);
			}
		}
		else if(strcmp(argv[i],"-tm") == 0)
		{
			options.testing = true;
		}
		else if(strcmp(argv[i],"-h") == 0 || strcmp(argv[i],"--help") == 0 || strcmp(argv[i],"help") == 0)
		{
				printf("-n <int> : number of core to use.\n");
				printf("-a <int> : kind of analysis to use {0: none, 1: diff, 2: linear}.\n");
				printf("-----------------\n");
				printf("-tm : testing mode.\n");
				exit(1);
		}
		else
		{
			printf("Argument %d:%s\n",i,argv[i]);
		}
	}

	return options;
}