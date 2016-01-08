#pragma once
#include "../includes/typedef.h"
#include "../includes/cipher.h"
#include "../includes/cryptanalysis.h"
#include "../tools/crypto_tools.h"
#include <utility>
#include <algorithm>
#include <vector>

class Differential : public Cryptanalysis
{
	Cipher* _cipher;
	
	int* _equations;
	std::pair<int,std::pair<int,int>>* _results;
	int _size_in;
	int _size_out;
	int _threshold = 4;

	void printEquation(int Xi, int Yi);

	static bool compare (std::pair<int,std::pair<int,int>> a,std::pair<int,std::pair<int,int>> b)
	{
		return ( std::get<0>(a) >  std::get<0>(b));
	}

	inline int idx(int i, int j) {
		// return i * (1 << _size_in) + j; 
		return (i << _size_out) + j; 
	};

	inline int getrow(int index) {
		return (index >> _size_out); 
	};

	inline int getcol(int index) {
		return ((1 << _size_out) - 1) & index; 
	};


	public:
		Differential(Cipher* cipher, int size_in, int size_out) : Cryptanalysis(), _cipher(cipher), _size_in(size_in), _size_out(size_out)
		{
			_equations = new int[1 << (size_in + size_out)]{};
			_results = new std::pair<int,std::pair<int,int>>[1 << (size_in + size_out)]{};
		};
		~Differential()
		{
			delete _equations;
			delete _results;
		};

		void generateTable();

		void analysis(bool zeroes = false);

		void sort();
};