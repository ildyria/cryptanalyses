#pragma once
#include <utility>
#include "../includes/bloc.h"
#include "../includes/typedef.h"
#include "../includes/cipher.h"
#include "../tools/crypto_tools.h"

// caracteristics of Des
// 64 bits key (effectively 56 bits)
// 16 x 48 bits sub-key
// 2 x 32 bits blocs (Feistel-based)
// 16 rounds
// require key-schedule
// 8 S box and P box with expension

using std::pair;

class Des : public Cipher
{

	uint64* keys;

	uint64 fkey(uint32 alpha, uint32 beta);

	void keyschedule();

	uint32 roundf(uint32 message, uint16 key);

	void round(pair<uint32,uint32>* input, int num);
	void unround(pair<uint32,uint32>* input, int num);

public:

	Des(uint64 key, int rounds) : Cipher(key, rounds) {
		keys = new uint64[rounds] {};
		keyschedule();
	};
	~Des() {};

	uint64 encrypt(uint64 b) override;

	uint64 decrypt(uint64 b) override;

	void test() override;

	void print(uint64 b);
};