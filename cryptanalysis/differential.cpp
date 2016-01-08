#include "differential.h"

void Differential::printEquation(int Xi, int Yi)
{
	Crypto_tools::print(Xi,_size_in);
	printf(" => ");
	Crypto_tools::print(Yi,_size_out);
}

void Differential::generateTable() {
	int res = 0;
	#pragma omp parallel for
	for (int i = 0; i < 1 << _size_in; ++i)
	{
		for (int j = 0; j < 1 << _size_in; ++j)
		{
			res = _cipher->apply_s(i,1) ^ _cipher->apply_s(i^j,1);
			#pragma omp atomic
			_equations[idx(j,res)]++;;
		}
	}
}

void Differential::printTable(bool zeroes) {
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

void Differential::sort(bool print) {
	for (int i = 0; i < (1 << (_size_in + _size_out)); ++i)
	{
		_results[i] = std::pair<int,std::pair<int,int>>(_equations[i],std::pair<int,int>(getrow(i),getcol(i))); 
	}
	std::vector<std::pair<int,std::pair<int,int>>> res (_results,_results+(1 << (_size_in + _size_out)));
	std::sort(res.begin(), res.end(), Differential::compare);
	if(print)
	{
		for(auto it = res.begin() + 1; it != res.end(); it++)
		{
			if(std::get<0>(*it) > _threshold)
			{
				printEquation(std::get<0>(std::get<1>(*it)),std::get<1>(std::get<1>(*it)));
				printf(" : %i / %i\n", std::get<0>(*it), 1<<_size_in);
			}
		}
	}
}

void Differential::attack() {
	printf("Comming Soon...\n");
}