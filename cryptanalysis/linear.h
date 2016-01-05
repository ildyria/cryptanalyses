#pragma once
#include "../includes/typedef.h"
#include "../includes/cipher.h"

class Linear
{
	Cipher* _cipher;
	
	int* _equations;
	int _size_in;
	int _size_out;

	void printEquation(int Xi, int Yi);

	inline int idx(int i, int j) {
		// return i * (1 << _size_in) + j; 
		return (i << _size_in) + j; 
	};

	public:
		Linear(Cipher* cipher, int size_in, int size_out) : _cipher(cipher), _size_in(size_in), _size_out(size_out)
		{
			_equations = new int[1 << (size_in + size_out)]{};
		};
		~Linear();

		void generateTable();

		void analysis(bool zeroes = false);

};