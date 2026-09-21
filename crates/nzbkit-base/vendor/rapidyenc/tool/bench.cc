#include <iostream>
#include <vector>
#include <chrono>

#include "../rapidyenc.h"

static const char* kernel_to_str(int k) {
	if(k == RYKERN_GENERIC) return "generic";
	if(k == RYKERN_SSE2) return "SSE2";
	if(k == RYKERN_SSSE3) return "SSSE3";
	if(k == RYKERN_AVX) return "AVX";
	if(k == RYKERN_AVX2) return "AVX2";
	if(k == RYKERN_VBMI2) return "VBMI2";
	if(k == RYKERN_NEON) return "NEON";
	if(k == RYKERN_PCLMUL) return "PCLMUL";
	if(k == RYKERN_VPCLMUL) return "VPCLMUL";
	if(k == RYKERN_ARMCRC) return "ARM-CRC";
	if(k == RYKERN_RVV) return "RVV";
	if(k == RYKERN_ARMPMULL) return "ARM-CRC + PMULL";
	if(k == RYKERN_ZBC) return "Zbkc";
	return "unknown";
}
#define ARTICLE_SIZE 768000ULL
#define SINGLE_OP_NUM 100
#define REPETITIONS 1000

int main(int, char**) {
	std::vector<unsigned char> data(ARTICLE_SIZE);
	std::vector<unsigned char> article(rapidyenc_encode_max_length(ARTICLE_SIZE, 128));
	size_t article_length;
	
	// fill with random data
	for(auto& c : data)
		c = rand() & 0xff;
	
	
	// encode benchmark
#ifndef RAPIDYENC_DISABLE_ENCODE
	rapidyenc_encode_init();
	{
		auto kernel = rapidyenc_encode_kernel();
		auto start = std::chrono::high_resolution_clock::now();
		for(int i=0; i<REPETITIONS; i++) {
			article_length = rapidyenc_encode(data.data(), article.data(), ARTICLE_SIZE);
		}
		auto stop = std::chrono::high_resolution_clock::now();
		float us = std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count();
		double speed = ARTICLE_SIZE * REPETITIONS;
		speed = speed / us / 1.048576;
		std::cerr << "Encode (" << kernel_to_str(kernel) << "): " << speed << " MB/s" << std::endl;
	}
#else
	{
		// do a pseudo yEnc encode to get a valid-ish article
		unsigned char* pOut = article.data();
		int col = 0;
		for(unsigned i=0; i<ARTICLE_SIZE; i++) {
			unsigned char c = data[i];
			if(c == 0 || c == '\r' || c == '\n' || c == '=' ||
			  (col == 0 && c == '.') ||
			  ((col % 128 == 0) && (c == '\t' || c == ' '))) {
				*pOut++ = '=';
				*pOut++ = c + 64;
				col++;
			} else {
				*pOut++ = c;
			}
			if(++col >= 128) {
				*pOut++ = '\r';
				*pOut++ = '\n';
				col = 0;
			}
		}
		article_length = pOut - article.data();
	}
#endif
	
	// decode
#ifndef RAPIDYENC_DISABLE_DECODE
	rapidyenc_decode_init();
	{
		auto kernel = rapidyenc_decode_kernel();
		auto start = std::chrono::high_resolution_clock::now();
		for(int i=0; i<REPETITIONS; i++) {
			rapidyenc_decode(article.data(), data.data(), article_length);
		}
		auto stop = std::chrono::high_resolution_clock::now();
		float us = std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count();
		double speed = article_length * REPETITIONS;
		speed = speed / us / 1.048576;
		std::cerr << "Decode (" << kernel_to_str(kernel) << "): " << speed << " MB/s" << std::endl;
	}
#endif
	
	// CRC
#ifndef RAPIDYENC_DISABLE_CRC
	rapidyenc_crc_init();
	{
		auto kernel = rapidyenc_crc_kernel();
		auto start = std::chrono::high_resolution_clock::now();
		for(int i=0; i<REPETITIONS; i++) {
			rapidyenc_crc(data.data(), ARTICLE_SIZE, 0);
		}
		auto stop = std::chrono::high_resolution_clock::now();
		float us = std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count();
		double speed = ARTICLE_SIZE * REPETITIONS;
		speed = speed / us / 1.048576;
		std::cerr << "CRC32 (" << kernel_to_str(kernel) << "): " << speed << " MB/s" << std::endl;
		
		// CRC 256pow
		std::vector<uint64_t> rnd_n(SINGLE_OP_NUM);
		std::vector<uint32_t> rnd_out(SINGLE_OP_NUM);
		for(auto& c : rnd_n)
			c = ((rand() & 0xffff) << 20) | (rand() & 0xfffff);  // 36-bit random numbers
		
		start = std::chrono::high_resolution_clock::now();
		for(int i=0; i<REPETITIONS; i++) {
			for(unsigned j=0; j<SINGLE_OP_NUM; j++)
				rnd_out[j] = rapidyenc_crc_256pow(rnd_n[j]);
		}
		stop = std::chrono::high_resolution_clock::now();
		us = std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count();
		speed = SINGLE_OP_NUM * REPETITIONS;
		speed = speed / us;
		std::cerr << "CRC32 256^n: " << speed << " Mop/s" << std::endl;
	}
#endif
	
	return 0;
}
