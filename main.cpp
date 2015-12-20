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

	Easy1* easy_cipher = new Easy1(0x0,1);

	Timer t = Timer();
	t.start();
	printf("result : \n");
	auto cipher = easy_cipher->encrypt(1);
	printf("result of encrypt :\n");
	easy_cipher->print(cipher);
	printf("====================\n");
	auto decrypt = easy_cipher->decrypt(cipher);
	printf("result of decrypt :\n");
	easy_cipher->print(decrypt);
	printf("\n");

	// uint64 toencrypt = 1;
	// for (int i = 0; i < 36; ++i)
	// {
	// 	printf("%i\n",i);
	// 	easy_cipher->print(toencrypt);
	// 	auto temp = easy_cipher->encrypt(toencrypt);
	// 	easy_cipher->print(temp);
	// 	temp = easy_cipher->decrypt(temp);
	// 	easy_cipher->print(temp);
	// 	printf("====================\n");

	// 	toencrypt <<= 1;
	// }

	t.stop();

	easy_cipher->print_boxes();

	printf("done in : %.3lf ms\n", t.resultmus()/1000.0);

	return 0;
}