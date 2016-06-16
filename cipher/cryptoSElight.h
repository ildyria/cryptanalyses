#pragma once
#include "../includes/typedef.h"
#include "../includes/cipher.h"
#include "../tools/crypto_tools.h"

// caracteristics of cryptoSElight
// 18 bits key
// 6 bits S box x 6
// 36 bits P box
// Round : S box -> P box -> Xor(key || key)

class cryptoSElight : public Cipher
{
	uint8 sbox[16] = {7,3,6,1,13,9,10,11,2,12,0,4,5,15,8,14};

	uint8 inv_sbox[16];

	uint64 apply_key(uint64 input);

	uint64 round(uint64 input);
	uint64 unround(uint64 input);

	void print_boxes();

	uint8 apply_sbox(uint8 index);
	uint8 unapply_sbox(uint8 index);
public:

	cryptoSElight(uint64 key, int rounds) : Cipher((key & 0xffffffff), rounds) {
		Crypto_tools::inv_box(sbox, inv_sbox, 16);
	};
	~cryptoSElight() {};

	uint64 encrypt(uint64 b) override;

	uint64 decrypt(uint64 b) override;

	void test() override;

	void print(uint64 b);

	uint64 unround1(uint64 b, uint64 k) override;

	uint8 apply_s(uint16 input, int box = 1) override
	{
		return apply_sbox(input);
	}
};