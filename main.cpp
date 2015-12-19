#include <iostream>
#include <stdio.h>
#include <gmp.h>
#include <string>
#include "includes/typedef.h"
#include "includes/args.h"
#include "includes/cipher.h"
// #include "tools/prime_list.h"
#include "tools/big_int.h"
#include "tools/Timer.h"
#include "cipher/easy1.h"

int main(int argc, char const *argv[])
{
	printf("\n \t \tIf it compiles then it works !\n");
	printf("\t But remember, all code is guilty until proven innocent !\n");
	printf("\t \tWhen in doubt, use Brute force ! - Ken Thompson\n \n");

	// int problem_chosen = read_args(argc, argv);

	Easy1* easy_cipher = new Easy1();

	Timer t = Timer();
	t.start();
	printf("result : \n");
	easy_cipher->print(easy_cipher->encrypt(1));
	printf("\n");
	t.stop();

	printf("done in : %.3lf ms\n", t.resultmus()/1000.0);

	return 0;
}