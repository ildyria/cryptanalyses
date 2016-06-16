#include <iostream>
#include <stdio.h>
#include <string>
#include "includes/typedef.h"
#include "includes/args.h"
#include "includes/cipher.h"
// #include "tools/prime_list.h"
#include "tools/big_int.h"
#include "tools/timer.h"
#include "tools/random.h"
#include "cryptanalysis/linear.h"
#include "cryptanalysis/differential.h"

#include "cipher/easy1.h"
#include "cipher/cryptoSElight.h"
#include "cipher/feal.h"
#include "cipher/des.h"
#include "cipher/SboxProd.h"
#include "cipher/SboxAES.h"

int main(int argc, char const *argv[])
{
	printf("\n \t \tIf it compiles then it works !\n");
	printf("\t But remember, all code is guilty until proven innocent !\n");
	printf("\t \tWhen in doubt, use Brute force ! - Ken Thompson\n \n");

	prog_options options = read_args(argc, argv);
	Timer t = Timer();
	Random::I(0);

	if(options.testing)
	{
		t.start();
		switch(options.cipher_type) {
			case 1:
				printf("Easy1\n");
				Crypto_tools::testCipher<Easy1>(0xf0f0f0f,3,0,0);
				break;

			case 2:
				printf("Feal\n");
				printf("Feal-8 : \n");
				Crypto_tools::testCipher<Feal>(0x0123456789abcdef,8,0,0xCEEF2C86F2490752);
				printf("Feal-16 : \n");
				Crypto_tools::testCipher<Feal>(0x0123456789abcdef,16,0,0x3ADE0D2AD84D0B6F);
				printf("Feal-32 : \n");
				Crypto_tools::testCipher<Feal>(0x0123456789abcdef,32,0,0x69B0FAE6DDED6B0B);
				break;

			case 3:
				printf("Des\n");
				Crypto_tools::testCipher<Des>(0x133457799bbcdff1,16,0x0123456789abcdef,0x85E813540F0AB405);
				Crypto_tools::testCipher<Des>(0x8000000000000000,16,0,0x95A8D72813DAA94D);
				Crypto_tools::testCipher<Des>(0x4000000000000000,16,0,0x0EEC1487DD8C26D5);
				Crypto_tools::testCipher<Des>(0x2000000000000000,16,0,0x7AD16FFB79C45926);
				Crypto_tools::testCipher<Des>(0x1000000000000000,16,0,0xD3746294CA6A6CF3);
				break;

			case 4:
				printf("cryptoSElight\n");
				Crypto_tools::testCipher<cryptoSElight>(0xf0f0f0f0,5,0,0);
				break;

			case 5:
				printf("SboxProd\n");
				break;

			case 6:
				printf("SboxAES\n");
				break;

			default:
				printf("Easy1\n");
				Crypto_tools::testCipher<Easy1>(0xf0f0f0f,3,0,0);
		}
		t.stop();
		printf("done in : %.3lf ms\n", t.resultmus()/1000.0);
		printf("------------------------------------------------------------\n");
	}

	Cipher* device;
	device_properties properties;
	switch(options.cipher_type) {
		case 1:
			printf("Easy1\n");
			device = new Easy1(0xf0f0f0f,3);
			properties.input_size = 6;
			properties.output_size = 6;
			properties.sbox_selected = 1;
			break;

		case 2:
			printf("Feal\n");
			device = new Feal(0x0123456789abcdef,8);
			properties.input_size = 16;
			properties.output_size = 4;
			properties.sbox_selected = 1;
			break;

		case 3:
			printf("Des\n");
			device = new Des(0x133457799bbcdff1);
			properties.input_size = 6;
			properties.output_size = 4;
			properties.sbox_selected = 1;
			break;

		case 4:
			printf("cryptoSElight\n");
			device = new cryptoSElight(0xf0f0f0fc,5);
			// device->test();
			properties.input_size = 4;
			properties.output_size = 4;
			properties.sbox_selected = 1;
			break;

		case 5:
			printf("SboxProd\n");
			device = new SboxProd();
			// device->test();
			properties.input_size = 8;
			properties.output_size = properties.input_size;
			properties.sbox_selected = properties.input_size;
			break;

		case 6:
			printf("SboxAES\n");
			device = new SboxAES();
			// device->test();
			properties.input_size = 8;
			properties.output_size = properties.input_size;
			properties.sbox_selected = properties.input_size;
			break;

		default:
			device = new Easy1(0xf0f0f0f,3);
			properties.input_size = 6;
			properties.output_size = 6;
			properties.sbox_selected = 1;
			printf("Easy1\n");
	}
	// device->test();

	Cryptanalysis* cryptlys;

	t.start();
	if(options.cryptanalysis_type == 1)
	{
		printf("Linear Cryptanalysis\n");
		cryptlys = new Linear(device,properties.input_size,properties.output_size);
		cryptlys->generateTable(properties.sbox_selected);
	}
	else if(options.cryptanalysis_type == 2)
	{
		printf("Differential Cryptanalysis\n");
		cryptlys = new Differential(device,properties.input_size,properties.output_size);
		cryptlys->generateTable(properties.sbox_selected);
		// cryptlys->attack();
	}

	if(options.cryptanalysis_type == 1 || options.cryptanalysis_type == 2)
	{
		cryptlys->printTable();
		cryptlys->sort(true);
	}

	t.stop();
	printf("done in : %.3lf ms\n", t.resultmus()/1000.0);
	printf("------------------------------------------------------------\n");

	return 0;
}