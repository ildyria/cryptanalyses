#pragma once
#include <stdint.h>

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;


typedef struct prog_options {
	uint8 cipher_type; //1
	uint8 cryptanalysis_type; //1
	uint8 cryptanalysis_solve; //1

	uint8 num_proc_to_use;
	bool testing;

} prog_options;

typedef struct device_properties {
	uint8 input_size;
	uint8 output_size;
} device_properties;