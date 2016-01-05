/**
 * \file Random.h
 * \brief Define singleton Random
 * \author Benoit Viguier
 * \version 1.0
 * \date November 2nd 2014
 *
 */
#pragma once
#include "typedef.h"
#include <stdint.h>
#include <random>
#include <ctime>

/**
 * \brief Random class : SINGLETON
 * \details 
	static unsigned int _seed : seed used to initialize the srand(), by default time(null);
	static Random* UniqueInstance : instance of the following class;
 */
class Random
{
	static uint64_t _seed;
	static Random* UniqueInstance;
	static std::mt19937_64 rng;

	explicit Random(uint64_t new_seed = std::mt19937_64::default_seed);
	~Random();
public:
	
	/**
	 * \fn I
	 * \brief get the instance of the singleton.
	 * \param  seed optionnal, allow us to set the seed in case singleton hasn't been initialized
	 * \return      the object.
	 */
	static inline Random* I(uint64_t seed = 0) {
			if (UniqueInstance != nullptr)
			{
				return UniqueInstance;
			}

			if (seed == 0)
			{
				UniqueInstance = new Random(time(nullptr));
			}
			else
			{
				UniqueInstance = new Random(seed);
			}
			return UniqueInstance;
		};

	/**
	 * \fn get
	 * \brief return a x64 number
	 *  
	 * \return random x64 integer
	 */
	inline uint64_t get() {
		return rng();
	}

	/**
	 * \fn get_min_max
	 * \brief returns an interger random number between min and max included.
	 * \param  min minimum integer to be returned
	 * \param  max maximum integer to be returned
	 * \return     random integer 
	 */
	inline int get_min_max(int min, int max) {
		int n = rng() % (max - min + 1) + min;
		return n;
	}

};
