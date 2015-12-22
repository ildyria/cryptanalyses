#pragma once
#include "../includes/typedef.h"
#include "../includes/cipher.h"
#include "../tools/crypto_tools.h"

// caracteristics of Easy1
// 18 bits key
// 6 bits S box x 6
// 36 bits P box
// Round : S box -> P box -> Xor(key || key)

class Easy1 : public Cipher
{
	uint8 sbox[64] = {16, 42, 28, 3, 26, 0, 31, 46, 27, 14, 49, 62, 37, 56, 23, 6, 40, 48, 53, 8,
					20, 25, 33, 1, 2, 63, 15, 34, 55, 21, 39, 57, 54, 45, 47, 13, 7, 44, 61, 9,
					60, 32, 22, 29, 52, 19, 12, 50, 5, 51, 11, 18, 59, 41, 36, 30, 17, 38, 10, 4,
					58, 43, 35, 24};
	uint8 pbox[36] = {24, 5, 15, 23, 14, 32, 19, 18, 26, 17, 6, 12, 34, 9, 8, 20, 28, 0, 2, 21, 29,
					11, 33, 22, 30, 31, 1, 25, 3, 35, 16, 13, 27, 7, 10, 4};
	uint8 inv_sbox[64];
	uint8 inv_pbox[36];

	uint8 apply_sbox(uint8 index);
	uint8 unapply_sbox(uint8 index);

	uint64 apply_key(uint64 input);

	uint64 round(uint64 input);
	uint64 unround(uint64 input);

	void print_boxes();

public:

	Easy1(uint64 key, uint64 rounds) : Cipher(((key & 0x3f) << 18) | (key & 0x3f), rounds) {
		Crypto_tools::inv_box(pbox, inv_pbox, 36);
		Crypto_tools::inv_box(sbox, inv_sbox, 64);
	};
	~Easy1() {};

	uint64 encrypt(uint64 b) override;

	uint64 decrypt(uint64 b) override;

	void test() override;

	void print(uint64 b);
};