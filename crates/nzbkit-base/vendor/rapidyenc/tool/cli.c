#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "../rapidyenc.h"

static int print_usage(const char *app) {
	fprintf(stderr, "Sample rapidyenc application\n");
	fprintf(stderr, "Usage: %s {e|d}\n", app);
	fprintf(stderr, "  (e)ncodes or (d)ecodes stdin to stdout\n");
	return 1;
}

#define BUFFER_SIZE 65536
#define LINE_SIZE 128

int main(int argc, char **argv) {
	if(argc < 2)
		return print_usage(argv[0]);
	if(argv[1][0] != 'e' && argv[1][0] != 'd')
		return print_usage(argv[0]);
	
#ifdef RAPIDYENC_DISABLE_ENCODE
	if(argv[1][0] == 'e') {
		fprintf(stderr, "encoder has been disabled in this build\n");
		return 1;
	}
#endif
#ifdef RAPIDYENC_DISABLE_DECODE
	if(argv[1][0] == 'd') {
		fprintf(stderr, "decoder has been disabled in this build\n");
		return 1;
	}
#endif
	
	FILE* infile = stdin; // fopen("", "rb");
	if(!infile) {
		fprintf(stderr, "error opening input: %s\n", strerror(errno));
		return 1;
	}
	FILE* outfile = stdout; // fopen("", "wb");
	if(!outfile) {
		fprintf(stderr, "error opening output: %s\n", strerror(errno));
		fclose(infile);
		return 1;
	}
	
	void* data = malloc(BUFFER_SIZE);
	if(!data) {
		fprintf(stderr, "error allocating input buffer\n");
		fclose(infile);
		fclose(outfile);
		return 1;
	}
	
#ifndef RAPIDYENC_DISABLE_CRC
	rapidyenc_crc_init();
	uint32_t crc = 0;
#endif
	int has_error = 0;
	
#ifndef RAPIDYENC_DISABLE_ENCODE
	if(argv[1][0] == 'e') {
		void* output = malloc(rapidyenc_encode_max_length(BUFFER_SIZE, LINE_SIZE));
		if(!output) {
			fprintf(stderr, "error allocating output buffer\n");
			fclose(infile);
			fclose(outfile);
			free(data);
			return 1;
		}
		rapidyenc_encode_init();
		
		int column = 0;
		while(1) {
			size_t read = fread(data, 1, BUFFER_SIZE, infile);
			int eof = feof(infile);
			if(read < BUFFER_SIZE && !eof) {
				if(ferror(infile)) {
					fprintf(stderr, "error reading input\n");
				} else {
					fprintf(stderr, "error: got zero bytes when reading input\n");
				}
				has_error = 1;
				break;
			}
			size_t out_len = rapidyenc_encode_ex(LINE_SIZE, &column, data, output, read, eof);
#ifndef RAPIDYENC_DISABLE_CRC
			crc = rapidyenc_crc(data, read, crc);
#endif
			if(fwrite(output, 1, out_len, outfile) != out_len) {
				fprintf(stderr, "error writing output\n");
				has_error = 1;
				break;
			}
			if(eof) break;
		}
		free(output);
	}
#endif
#ifndef RAPIDYENC_DISABLE_DECODE
	if(argv[1][0] == 'd') {
		rapidyenc_decode_init();
		
		RapidYencDecoderState state = RYDEC_STATE_CRLF;
		while(1) {
			size_t read = fread(data, 1, BUFFER_SIZE, infile);
			RapidYencDecoderEnd ended;
			void* in_ptr = data;
			void* out_ptr = data;
			int eof = feof(infile);
			if(read < BUFFER_SIZE && !eof) {
				if(ferror(infile)) {
					fprintf(stderr, "error reading input\n");
				} else {
					fprintf(stderr, "error: got zero bytes when reading input\n");
				}
				has_error = 1;
				break;
			}
			ended = rapidyenc_decode_incremental((const void**)&in_ptr, &out_ptr, read, &state);
			size_t out_len = (uintptr_t)out_ptr - (uintptr_t)data;
#ifndef RAPIDYENC_DISABLE_CRC
			crc = rapidyenc_crc(data, out_len, crc);
#endif
			if(fwrite(data, 1, out_len, outfile) != out_len) {
				fprintf(stderr, "error writing output\n");
				has_error = 1;
				break;
			}
			
			if(ended != RYDEC_END_NONE || eof) {
				if(ended == RYDEC_END_CONTROL)
					fprintf(stderr, "yEnc control line found\n");
				else if(ended == RYDEC_END_ARTICLE)
					fprintf(stderr, "End-of-article marker found\n");
				else
					fprintf(stderr, "End of input reached\n");
				break;
			}
		}
	}
#endif
	
	fclose(infile);
	fclose(outfile);
	free(data);
	
	if(!has_error) {
#ifndef RAPIDYENC_DISABLE_CRC
		fprintf(stderr, "Computed CRC32: %08x\n", crc);
#endif
	}
	
	return has_error;
}
