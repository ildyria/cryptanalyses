#include "feal.h"


uint32 Feal::fkey(uint32 alpha, uint32 beta){
	uint8 atab[4] = {0,0,0,0};
	uint8 btab[4] = {0,0,0,0};
	uint8 fk[4] = {0,0,0,0};

	Crypto_tools::spliti<uint64,uint8,8,4,0xff>(alpha,atab);
	// printf("%02x",atab[0]);
	// printf(" %02x",atab[1]);
	// printf(" %02x",atab[2]);
	// printf(" %02x\n",atab[3]);

	Crypto_tools::spliti<uint64,uint8,8,4,0xff>(beta,btab);
	// printf("%02x",btab[0]);
	// printf(" %02x",btab[1]);
	// printf(" %02x",btab[2]);
	// printf(" %02x\n",btab[3]);

	fk[1] = sbox(atab[0] ^ atab[1], atab[2] ^ atab[3] ^ btab[0] , 1);
	fk[2] = sbox(atab[2] ^ atab[3], fk[1] ^ btab[1], 0);
	fk[0] = sbox(atab[0], fk[1] ^ btab[2], 0);
	fk[3] = sbox(atab[3], fk[2] ^ btab[3], 1);
	// printf("%02x",fk[0]);
	// printf(" %02x",fk[1]);
	// printf(" %02x",fk[2]);
	// printf(" %02x\n",fk[3]);

	return Crypto_tools::joini<uint8,uint64,8,4,0xff>(fk);
}


void Feal::keyschedule() {
	uint32 a = (_key >> 32) & 0xffffffff;
	uint32 b = _key & 0xffffffff;
	// printf("a = %08x\n",a);
	// printf("b = %08x\n",b);
	
	uint32 apre = 0;
	uint32 bin = 0;
	uint32 tempkey = 0;
	for(uint i = 0; i < (_rounds + 8)/2 ; ++i)
	{
		// printf("---------------\n");

		// printf("a = %08x\n",a);
		// printf("b = %08x\n",b);
		// printf("apre = %08x\n",apre);
		bin = b ^ apre;
		apre = a;
		// printf("bin = %08x\n",bin);
		tempkey = fkey(a,bin);
		// printf("Ktemp = %08x\n",tempkey);
		keys[2*i] = (tempkey >> 16) & 0xffff;
		keys[2*i+1] = tempkey & 0xffff;
		a = b;
		b = tempkey;
	}
}

uint32 Feal::roundf(uint32 message, uint16 key){
	uint8 mtab[4] = {0,0,0,0};
	uint8 ktab[2] = {0,0};

	Crypto_tools::spliti<uint64,uint8,8,4,0xff>(message,mtab);
	Crypto_tools::spliti<uint64,uint8,8,2,0xff>(key,ktab);

	uint8 output[4] = {0,0,0,0};

	output[1] = mtab[1] ^ ktab[0] ^ mtab[0];
	output[2] = mtab[2] ^ ktab[1] ^ mtab[3];
	output[1] = sbox(output[1], output[2], 1);
	output[2] = sbox(output[2], output[1], 0);
	output[0] = sbox(mtab[0], output[1], 0);
	output[3] = sbox(mtab[3], output[2], 1);

	return Crypto_tools::joini<uint8,uint64,8,4,0xff>(output);
}

void Feal::round(pair<uint32,uint32>* input, int num){
	printf("-------------------------------------\n");
	printf("L%i : %08x | R%i : %08x\n",num,input->first,num,input->second);
	uint32 R = input->second;
	input->second = input->first ^ roundf(input->second,keys[num]);
	input->first = R;
	printf("L%i : %08x | R%i : %08x\n",num + 1,input->first,num + 1,input->second);
}

void Feal::unround(pair<uint32,uint32>* input, int num){
	printf("-------------------------------------\n");
	printf("L%i : %08x | R%i : %08x\n",(_rounds - num),input->first,(_rounds - num),input->second);
	uint32 R = input->first;
	input->first = input->second ^ roundf(input->first,keys[_rounds - 1 - num]);
	input->second = R;
	printf("L%i : %08x | R%i : %08x\n",(_rounds - 1 - num),input->first,(_rounds - 1 - num),input->second);
}


uint64 Feal::encrypt(uint64 input) {

	pair<uint32,uint32>* LR = new pair<uint32,uint32>((input >> 32) & 0xffffffff,input & 0xffffffff); 			// (L0,R0) <- (ML,MR)
	printf("L%i : %08x | R%i : %08x\n",0,LR->first,0,LR->second);

	LR->first = LR->first ^ Crypto_tools::concat<uint16,uint32>(keys[_rounds],keys[_rounds+1]);					// L0 <- L0 ^ K8||K9
	LR->second = LR->second ^ Crypto_tools::concat<uint16,uint32>(keys[_rounds+2],keys[_rounds+3]);				// R0 <- R0 ^ K10||K11
	printf("L%i : %08x | R%i : %08x\n",0,LR->first,0,LR->second);
	LR->second = LR->second ^ LR->first;																		// R0 <- R0 ^ L0

	for (uint i = 0; i < _rounds; ++i)
	{																											// L1 <- R0
		round(LR,i);																							// R1 <- L0 ^ f(R0,K0)
	}

	LR->first = LR->first ^ LR->second;																			// L8 <- L8 ^ R8

	LR->second = LR->second ^ Crypto_tools::concat<uint16,uint32>(keys[_rounds + 4],keys[_rounds + 5]);	// R8 <- R8 ^ K12||K13
	LR->first = LR->first ^ Crypto_tools::concat<uint16,uint32>(keys[_rounds + 6],keys[_rounds + 7]);	// L8 <- L8 ^ K14||K15

	return Crypto_tools::concat<uint32,uint64>(LR->second,LR->first);											// R8 || L8 (/!\ swap)
}

uint64 Feal::decrypt(uint64 input) {
	pair<uint32,uint32>* LR = new pair<uint32,uint32>(input & 0xffffffff,(input >> 32) & 0xffffffff); 			// (L8,R8) <- (CL,CR)
	printf("L%i : %08x | R%i : %08x\n",_rounds,LR->first,_rounds,LR->second);

	LR->second = LR->second ^ Crypto_tools::concat<uint16,uint32>(keys[_rounds + 4],keys[_rounds + 5]);	// R8 <- R8 ^ K12||K13
	LR->first = LR->first ^ Crypto_tools::concat<uint16,uint32>(keys[_rounds + 6],keys[_rounds + 7]);	// L8 <- L8 ^ K14||K15
	printf("L%i : %08x | R%i : %08x\n",_rounds,LR->first,_rounds,LR->second);

	LR->first = LR->first ^ LR->second;																			// L8 <- L8 ^ R8

	for (uint i = 0; i < _rounds; ++i)
	{																											// L1 <- R0
		unround(LR,i);																							// R1 <- L0 ^ f(R0,K0)
	}

	LR->second = LR->second ^ LR->first;																		// R0 <- R0 ^ L0

	LR->first = LR->first ^ Crypto_tools::concat<uint16,uint32>(keys[_rounds],keys[_rounds+1]);					// L0 <- L0 ^ K8||K9
	LR->second = LR->second ^ Crypto_tools::concat<uint16,uint32>(keys[_rounds+2],keys[_rounds+3]);				// R0 <- R0 ^ K10||K11

	return Crypto_tools::concat<uint32,uint64>(LR->second,LR->first);											// R8 || L8 (/!\ swap)
}

void Feal::print(uint64 input)
{
	printf("%lx\n",input);
}

void Feal::test(){
	uint64 toencrypt = 0;
	printf("to cipher : %016lx\n",toencrypt);
	printf("====================\n");
	auto ciphered = encrypt(toencrypt);
	printf("====================\n");
	printf("ciphered : %016lx\n",ciphered);
	printf("====================\n");
	auto deciphered = decrypt(ciphered);
	printf("====================\n");
	printf("deciphered : %016lx\n",deciphered);
	printf("====================\n");
	printf("cipher must match : ceef2c86f2490752\n");
	printf("cipher match ? %s\n",(ciphered == 0xceef2c86f2490752) ? "yes" : "no");
	printf("plain and decrypt match ? %s\n",(0 == deciphered) ? "yes" : "no");
	printf("====================\n");

	for (uint i = 0; i < _rounds*2; ++i)
	{
		printf("K%i = %04x\n",i,keys[i]);
	}
	printf("########################\n");
}
