#pragma once
#include <utility>
#include "../includes/bloc.h"
#include "../includes/typedef.h"
#include "../includes/cipher.h"
#include "../tools/crypto_tools.h"

// caracteristics of Feal
// 64 bits key
// 2 x 32 bits blocs (Feistel-based)
// 8 rounds
// require key-schedule
// no S box but a function : rot2((x + y + delta) & 0xff)

using std::pair;

class Feal : public Cipher
{
	inline uint8 sbox(uint8 x, uint8 y, uint8 delta) {
		return Crypto_tools::rot2<uint8>((x + y + delta) & 0xff);
	};

	uint32 roundf(uint32 alpha, uint32 beta);

	pair<uint32,uint32>* round(pair<uint32,uint32>* input);
	pair<uint32,uint32>* unround(pair<uint32,uint32>* input);

public:

	Feal(uint64 key, uint64 rounds) : Cipher(key, rounds) {
	};
	~Feal() {};

	uint64 encrypt(uint64 b) override;

	uint64 decrypt(uint64 b) override;

	void test() override;

	void print(uint64 b);
};