#include "differential.h"

void Differential::printEquation(int Xi, int Yi)
{
	Crypto_tools::print(Xi,_size_in);
	printf(" => ");
	Crypto_tools::print(Yi,_size_out);
}

void Differential::generateTable(int SboxNum) {
	int res = 0;
	#pragma omp parallel for
	for (int i = 0; i < 1 << _size_in; ++i)
	{
		for (int j = 0; j < 1 << _size_in; ++j)
		{
			res = _cipher->apply_s(i,SboxNum) ^ _cipher->apply_s(i^j,SboxNum);
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
		printf("%3x ", j);
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
		printf(" %2x | ", i);
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
		int printed = 0;
		for(auto it = res.begin() + 1; it != res.end(); it++)
		{
			if(std::get<0>(*it) > _threshold && printed < _print_num)
			{
				printEquation(std::get<0>(std::get<1>(*it)),std::get<1>(std::get<1>(*it)));
				printf(" : %i / %i\n", std::get<0>(*it), 1<<_size_in);
				printed ++;
			}
		}
	}
}

void Differential::attack() {

	uint64 plain;
    uint64 r1, r2, c1, c2;
    std::vector<uint64> res = std::vector<uint64>(16,0);
	for (uint64 i = 0; i < _num_target; ++i)
	{
		plain = static_cast<unsigned int>(Random::I()->get());
		c1 = _cipher->encrypt(plain);
		c2 = _cipher->encrypt(plain ^ _diff_input);

		uint64 kt;
	    for(uint64 key=0; key < 16; key++){
	    	kt = key;
			kt = Crypto_tools::rotR<uint64,2,32,0xffffffff>(kt);
	        r1=_cipher->unround1(c1,kt);
	        r2=_cipher->unround1(c2,kt);
	       	r1 = Crypto_tools::rot<uint64,2,32,0xffffffff>(r1);
			r2 = Crypto_tools::rot<uint64,2,32,0xffffffff>(r2);
	        if(((r1^r2) & 15) == (_diff_target << 2)){
	            res[key]=res[key]+1;
	        }
	    }
	}
	uint64 kmax = 0;
	uint64 resm = 0;
	for(int key = 0; key < 16 ; key++)
	{
		if(res[key] > resm)
		{
			resm = res[key];
			kmax = key;
		}
		printf("%08X : %lu/%lu\n", key, res[key],_num_target);
	}
	printf("sub key guessed is : %08lX\n",kmax);

	printf("key was        : %08lX\n",_cipher->getkey());
}