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
		return Crypto_tools::rot<uint8,2>((x + y + delta) & 0xff);
	};

	uint16* keys;

	uint32 fkey(uint32 alpha, uint32 beta);

	void keyschedule();

	uint32 roundf(uint32 message, uint16 key);

	void round(pair<uint32,uint32>* input, int num);
	void unround(pair<uint32,uint32>* input, int num);

public:

	Feal(uint64 key, uint64 rounds) : Cipher(key, rounds) {
		keys = new uint16[2*rounds] {};
		keyschedule();
	};
	~Feal() {};

	uint64 encrypt(uint64 b) override;

	uint64 decrypt(uint64 b) override;

	void test() override;

	void print(uint64 b);
};