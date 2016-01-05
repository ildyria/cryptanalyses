#include "linear.h"

void Linear::printEquation(int Xi, int Yi)
{
	int mask = 1 << (_size_in - 1);
	for(int i = 0; i < _size_in; ++i)
	{
		if((Xi & mask) > 0)
		{
			if(i > 0) printf("\u2295 \n");
			printf("X%i ", i);
		}
		mask >>= 1;
	}
	printf("= ");
	mask = 1 << (_size_out - 1);
	for (int i = 0; i < _size_out; ++i)
	{
		if((Yi & mask) > 0)
		{
			if(i > 0) printf("\u2295 \n");
			printf("Y%i ", i);
		}
		mask >>= 1;
	}
}

void Linear::generateTable() {
	int max = 1 << _size_in;
	for (int i = 0; i < 1 << _size_in; ++i)
	{
		for (int j = 0; j < 1 << _size_out; ++j)
		{
			int res = 0;
			for (int k = 0; k < max; ++k)
			{
				if(Crypto_tools::XorBits(k & i,_size_in) == Crypto_tools::XorBits(_cipher->apply_s(k,1) & j, _size_out))
				{
					res ++;
				}
			}
			_equations[idx(i,j)] = res - (max >> 1);
		}
	}
}

void Linear::analysis(bool zeroes) {
	int val;
	printf("    | ");
	for (int j = 0; j < 1 << _size_out; ++j)
	{
		printf("%3i ", j);
	}
	printf("\n");
	printf("-----");
	for (int j = 0; j < 1 << _size_out; ++j)
	{
		printf("----");
	}
	printf("\n");
	for (int i = 0; i < 1 << _size_in; ++i)
	{
		printf(" %2i | ", i);
		for (int j = 0; j < 1 << _size_out; ++j)
		{
			val = _equations[idx(i,j)];
			if(val == 0 && !zeroes)
			{
				printf("    ");
			}
			else
			{
				printf("%3i ", val);
			}
		}
		printf("\n");
	}
}