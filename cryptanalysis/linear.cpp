#include "linear.h"

void Linear::printEquation(int Xi, int Yi)
{
	int mask = 1 << (_size_in - 1);
	bool print = false;
	for(int i = 0; i < _size_in; ++i)
	{
		if((Xi & mask) > 0)
		{
			if(print) printf("\u2295 ");
			printf("X%i ", i);
			print = true;
		}
		mask >>= 1;
	}
	printf("= ");
	print = false;
	mask = 1 << (_size_out - 1);
	for (int i = 0; i < _size_out; ++i)
	{
		if((Yi & mask) > 0)
		{
			if(print) printf("\u2295 ");
			printf("Y%i ", i);
			print = true;
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

void Linear::sort() {
	for (int i = 0; i < (1 << (_size_in + _size_out)); ++i)
	{
		_results[i] = std::pair<int,std::pair<int,int>>(_equations[i],std::pair<int,int>(getrow(i),getcol(i))); 
	}
	std::vector<std::pair<int,std::pair<int,int>>> res (_results,_results+(1 << (_size_in + _size_out)));
	std::sort(res.begin(), res.end(), Linear::compare);
	auto itb = res.begin();
	auto ite = res.end();
	ite--;
	itb++;
	while(itb < ite)
	{
		// printf("%i\n", (-1) * std::get<0>(*ite));
		if((-std::get<0>(*ite)) > std::get<0>(*itb))
		{
			printEquation(std::get<0>(std::get<1>(*ite)),std::get<1>(std::get<1>(*ite)));
			printf(" : %i\n", std::get<0>(*ite));
			ite--;
		}
		else if (std::get<0>(*itb) > _threshold)
		{
			printEquation(std::get<0>(std::get<1>(*itb)),std::get<1>(std::get<1>(*itb)));
			printf(" : %i\n", std::get<0>(*itb));
			itb++;
		}
		else if (std::get<0>(*ite) > -_threshold)
		{
			ite--;
		}
		else
		{
			itb++;
		}
	}
}
