#include "des.h"

void Des::generate_moves(uint8* tab, int size, uint8* moves, bool* way) {
	for (int i = 0; i < size; ++i)
	{
		way[i] = size - i > tab[i];
		if(way[i])
		{
			moves[i] = (size - i) - tab[i];
		}
		else
		{
			moves[i] = tab[i] - (size - i);
		}
	}
}


template<typename O, int size> O Des::apply_pbox(uint64 input, uint8* pbox, bool* way) {
	O output = 0;
	uint64 mask = static_cast<uint64>(1) << (size - 1);

	for (int i = 0; i < size; ++i)
	{
		if(way[i])
		{
			if((input & (mask >> pbox[i])) > 0)
			{
				// printf("%i - %i\n",i,pbox[i]);
				output = output | mask;
			}
		}
		else
		{
			if((input & (mask << pbox[i])) > 0)
			{
				// printf("%i - %i\n",i,pbox[i]);
				output = output | mask;
			}
		}
		mask >>= 1;
	}
	return output;
}

void Des::keyschedule() {
	// http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
	printf("key = \n");
	Crypto_tools::printn<64>(_key);

	uint32 left = apply_pbox<uint32,28>(_key,pc1_left_f,pc1_left_w);
	uint32 right = apply_pbox<uint32,28>(_key,pc1_right_f,pc1_right_w);

	printf("left = ");
	Crypto_tools::printn<28>(left);
	printf("right = ");
	Crypto_tools::printn<28>(right);

	for (int i = 0; i < 16; ++i)
	{
		printf("---------------\n");
		if(i == 0 || i == 1 || i == 8 || i == 15) // 1 2 9 16 : rot1
		{
			printf("%i : rot1\n",i);
			left = Crypto_tools::rot<uint32,1,28,0xfffffff>(left);
			right = Crypto_tools::rot<uint32,1,28,0xfffffff>(right);
		}
		else
		{
			printf("%i : rot2\n",i);
			left = Crypto_tools::rot<uint32,2,28,0xfffffff>(left);
			right = Crypto_tools::rot<uint32,2,28,0xfffffff>(right);
		}
		printf("left  = ");
		Crypto_tools::printn<28>(left);
		printf("right = ");
		Crypto_tools::printn<28>(right);
		uint64 key = Crypto_tools::concat<uint32,uint64,28>(left,right);
		keys[i] = apply_pbox<uint64,48>(key,pc2_f,pc2_w);
	}
}

uint8 Des::apply_sbox(uint8 sbox[4][16], uint8 val)
{
	uint8 row = (val & 1) | ((val >> 4) & 2);
	uint8 col = (val & 0x1e) >> 1;
	// printf("\n[%i][%i] = %i\n", row, col, sbox[row][col]);
	return sbox[row][col];
}

uint32 Des::roundf(uint32 message, uint64 key){
	uint64 extended = apply_pbox<uint64,48>(message,round_exp_f,round_exp_w);
	extended ^= key;
	// Crypto_tools::printn<48>(extended);
	// printf("%012lx\n", extended);
	uint8 substbox[8] = {0,0,0,0,0,0,0,0};
	Crypto_tools::spliti<uint64, uint8, 6, 8, 0x3f>(extended, substbox);

	// printf("1 : ");
	// Crypto_tools::print<6>(substbox[0]);
	substbox[0] = apply_sbox(S1,substbox[0]);
	// printf(" => %i\n", substbox[0]);

	// printf("2 : ");
	// Crypto_tools::print<6>(substbox[1]);
	substbox[1] = apply_sbox(S2,substbox[1]);
	// printf(" => %i\n", substbox[1]);

	// printf("3 : ");
	// Crypto_tools::print<6>(substbox[2]);
	substbox[2] = apply_sbox(S3,substbox[2]);
	// printf(" => %i\n", substbox[2]);

	// printf("4 : ");
	// Crypto_tools::print<6>(substbox[3]);
	substbox[3] = apply_sbox(S4,substbox[3]);
	// printf(" => %i\n", substbox[3]);

	// printf("5 : ");
	// Crypto_tools::print<6>(substbox[4]);
	substbox[4] = apply_sbox(S5,substbox[4]);
	// printf(" => %i\n", substbox[4]);

	// printf("6 : ");
	// Crypto_tools::print<6>(substbox[5]);
	substbox[5] = apply_sbox(S6,substbox[5]);
	// printf(" => %i\n", substbox[5]);

	// printf("7 : ");
	// Crypto_tools::print<6>(substbox[6]);
	substbox[6] = apply_sbox(S7,substbox[6]);
	// printf(" => %i\n", substbox[6]);

	// printf("8 : ");
	// Crypto_tools::print<6>(substbox[7]);
	substbox[7] = apply_sbox(S8,substbox[7]);
	// printf(" => %i\n", substbox[7]);
	message = Crypto_tools::joini<uint8, uint32, 4, 8, 0xf>(substbox);
	message = apply_pbox<uint32,32>(message,round_per_f,round_per_w);
	return message;
}

void Des::round(pair<uint32,uint32>* input, int num){
	printf("-------------------------------------\n");
	printf("L%i : %08x | R%i : %08x\n",num,input->first,num,input->second);
	uint32 R = input->second;
	input->second = input->first ^ roundf(input->second,keys[num]);
	input->first = R;
	printf("L%i : %08x | R%i : %08x\n",num + 1,input->first,num + 1,input->second);
}

void Des::unround(pair<uint32,uint32>* input, int num){
	printf("-------------------------------------\n");
	printf("L%i : %08x | R%i : %08x\n",(_rounds - num),input->first,(_rounds - num),input->second);
	uint32 R = input->first;
	input->first = input->second ^ roundf(input->first,keys[_rounds - 1 - num]);
	input->second = R;
	printf("L%i : %08x | R%i : %08x\n",(_rounds - 1 - num),input->first,(_rounds - 1 - num),input->second);
}


uint64 Des::encrypt(uint64 input) {

	input = apply_pbox<uint64,64>(input,iper_f,iper_w);															// first permutation
	pair<uint32,uint32>* LR = new pair<uint32,uint32>((input >> 32) & 0xffffffff,input & 0xffffffff); 			// (L0,R0) <- (ML,MR)
	printf("L%i : %08x | R%i : %08x\n",0,LR->first,0,LR->second);

	for (uint i = 0; i < _rounds; ++i)
	{																											// L1 <- R0
		round(LR,i);																							// R1 <- L0 ^ f(R0,K0)
	}

	input = Crypto_tools::concat<uint32,uint64>(LR->second,LR->first);											// R8 || L8 (/!\ swap)
	input = apply_pbox<uint64,64>(input,inv_iper_f,inv_iper_w);													// inverse permutation
	return input;
}

uint64 Des::decrypt(uint64 input) {
	input = apply_pbox<uint64,64>(input,iper_f,iper_w);															// inverse permutation

	pair<uint32,uint32>* LR = new pair<uint32,uint32>(input & 0xffffffff,(input >> 32) & 0xffffffff); 			// (L8,R8) <- (CL,CR)
	printf("L%i : %08x | R%i : %08x\n",_rounds,LR->first,_rounds,LR->second);

	for (uint i = 0; i < _rounds; ++i)
	{																											// L1 <- R0
		unround(LR,i);																							// R1 <- L0 ^ f(R0,K0)
	}
	input = Crypto_tools::concat<uint32,uint64>(LR->first,LR->second);											// R8 || L8 (/!\ swap) 
	input = apply_pbox<uint64,64>(input,inv_iper_f,inv_iper_w);													// first permutation
	return input;
}

void Des::print(uint64 input)
{
	printf("%lx\n",input);
}

void Des::test(){
	uint64 toencrypt1 = 0x4e6f772069732074;
	// uint64 toencrypt2 = 0x68652074696d6520;
	// uint64 toencrypt3 = 0x666f7220616c6c20;
	uint64 tomatch1 = 	0x3fa40e8a984d4815;
	// uint64 tomatch2 = 	0x6a271787ab8883f9;
	// uint64 tomatch3 = 	0x893d51ec4b563b53;
	printf("to cipher1 : %016lx\n",toencrypt1);
	// printf("to cipher2 : %016lx\n",toencrypt2);
	// printf("to cipher3 : %016lx\n",toencrypt3);
	printf("====================\n");
	uint64 ciphered1 = encrypt(toencrypt1);
	// auto ciphered2 = encrypt(toencrypt2);
	// auto ciphered3 = encrypt(toencrypt3);
	printf("====================\n");
	printf("ciphered1 : %016lx\n",ciphered1);
	// printf("ciphered2 : %016lx\n",ciphered2);
	// printf("ciphered3 : %016lx\n",ciphered3);
	printf("====================\n");
	uint64 deciphered1 = decrypt(ciphered1);
	// auto deciphered2 = decrypt(ciphered2);
	// auto deciphered3 = decrypt(ciphered3);
	printf("====================\n");
	printf("deciphered1 : %016lx\n",deciphered1);
	// printf("deciphered2 : %016lx\n",deciphered2);
	// printf("deciphered3 : %016lx\n",deciphered3);
	printf("====================\n");
	printf("cipher match ? %s\n",(ciphered1 == tomatch1) ? "yes" : "no");
	printf("plain and decrypt match ? %s\n",(toencrypt1 == deciphered1) ? "yes" : "no");
	// printf("cipher match ? %s\n",(ciphered1 == tomatch1 && ciphered2 == tomatch2 && ciphered3 == tomatch3) ? "yes" : "no");
	// printf("plain and decrypt match ? %s\n",(toencrypt1 == deciphered1 && toencrypt2 == deciphered2 && toencrypt3 == deciphered3) ? "yes" : "no");
	printf("====================\n");

	Crypto_tools::printn<64>(_key);
	for (uint i = 0; i < _rounds; ++i)
	{
		printf("K%i = ",i);
		Crypto_tools::printn<48>(keys[i]);
	}
	// for (uint i = 0; i < _rounds; ++i)
	// {
	// 	printf("K%i = %012lx\n",i,keys[i]);
	// }
	printf("########################\n");

	printf("iper\n");
	uint64 test = 1;
	uint64 res;
	int pos;
	for (int i = 0; i < 64; ++i)
	{
		res = apply_pbox<uint64,64>(test,iper_f,iper_w);
		pos = Crypto_tools::posi<uint64,64>(res);
		if (pos >= 0 && iper[pos] != i + 1)
		{
			printf("%i <> %i <> %i \n",pos,iper[pos],i + 1);
		}
		else if(pos == -1)
		{
			printf("!");
		}
		else
		{
			printf(".");
		}
		test <<= 1;
	}
	printf("\n");


	printf("inv_iper\n");
	test = 1;
	for (int i = 0; i < 64; ++i)
	{
		res = apply_pbox<uint64,64>(test,inv_iper_f,inv_iper_w);
		pos = Crypto_tools::posi<uint64,64>(res);
		if (pos >= 0 && inv_iper[pos] != i + 1)
		{
			printf("%i <> %i <> %i \n",pos,inv_iper[pos],i + 1);
		}
		else if(pos == -1)
		{
			printf("!");
		}
		else
		{
			printf(".");
		}
		test <<= 1;
	}
	printf("\n");


	printf("pc2\n");
	test = 1;
	for (int i = 0; i < 56; ++i)
	{
		res = apply_pbox<uint64,48>(test,pc2_f,pc2_w);
		pos = Crypto_tools::posi<uint64,48>(res);
		if (pos >= 0 && pc2[pos] != i + 1)
		{
			printf("%i <> %i <> %i \n",pos,inv_iper[pos],i + 1);
		}
		else if(pos == -1)
		{
			printf("!");
		}
		else
		{
			printf(".");
		}
		test <<= 1;
	}
	printf("\n");

	printf("round_exp\n");
	test = 1;
	for (int i = 0; i < 32; ++i)
	{
		res = apply_pbox<uint64,48>(test,round_exp_f,round_exp_w);
		pos = Crypto_tools::posi<uint64,48>(res);
		if (pos >= 0 && round_exp[pos] != i + 1)
		{
			printf("%i <> %i <> %i \n",pos,inv_iper[pos],i + 1);
		}
		else if(pos == -1)
		{
			printf("!");
		}
		else
		{
			printf(".");
		}
		test <<= 1;
	}
	printf("\n");

	printf("round_per\n");
	uint32 test2 = 1;
	uint32 res2;
	for (int i = 0; i < 32; ++i)
	{
		res2 = apply_pbox<uint32,32>(test2,round_per_f,round_per_w);
		pos = Crypto_tools::posi<uint32,32>(res2);
		if (pos >= 0 && round_per[pos] != i + 1)
		{
			printf("%i <> %i <> %i \n",pos,round_per[pos],i + 1);
		}
		else if(pos == -1)
		{
			printf("!");
		}
		else
		{
			printf(".");
		}
		test2 <<= 1;
	}
	printf("\n");

	printf("pc1_left\n");
	test = 1;
	for (int i = 0; i < 64; ++i)
	{
		res2 = apply_pbox<uint64,28>(test,pc1_left_f,pc1_left_w);
		pos = Crypto_tools::posi<uint32,28>(res2);
		if (pos >= 0 && pc1_left[pos] != i + 1)
		{
			printf("%i <> %i <> %i \n",pos,pc1_left[pos],i + 1);
		}
		else if(pos == -1)
		{
			printf("!");
		}
		else
		{
			printf(".");
		}
		test <<= 1;
	}
	printf("\n");

	printf("pc1_right\n");
	test = 1;
	for (int i = 0; i < 64; ++i)
	{
		res2 = apply_pbox<uint64,28>(test,pc1_right_f,pc1_right_w);
		pos = Crypto_tools::posi<uint32,28>(res2);
		if (pos >= 0 && pc1_right[pos] != i + 1)
		{
			printf("%i <> %i <> %i \n",pos,pc1_right[pos],i + 1);
		}
		else if(pos == -1)
		{
			printf("!");
		}
		else
		{
			printf(".");
		}
		test <<= 1;
	}
	printf("\n");

	printf("inversions\n");
	test = 1;
	for (int i = 0; i < 64; ++i)
	{
		res = apply_pbox<uint64,64>(test,iper_f,iper_w);
		res = apply_pbox<uint64,64>(res,inv_iper_f,inv_iper_w);
		if(res == test)
		{
			printf(".");
		}
		else
		{
			printf("!");
		}
		test <<= 1;
	}
	printf("\n");


}
