#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#define ROTL(x, n) ((x << n) | (x >> (32-n)))

void
MD5_engine(const unsigned char *text, 
           const int totat_blocks, 
           unsigned char *output) 
{
	/* first four initial constants of the digest */
	unsigned int a0 = 0x67452301, 
	             b0 = 0xefcdab89, 
	             c0 = 0x98badcfe, 
	             d0 = 0x10325476, 
	             block_no = 0;
	unsigned int chunks[16];
	unsigned int i, j;
	unsigned char block[64] = "\0";

	/* this is floor(2^32 * abs(sin(i + 1)), where i is from 0 to 63 */
	const unsigned int Constants[] = {
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,	
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391	
	};

	/* number of rotations to perform per 512 bit chunk per round*/
	const unsigned int rotations[] = {
		7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
		5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
		4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
		6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
	};

        
	while (block_no < totat_blocks) {
		/* copy the 64 byte block, and then move the pointer to the 
		 * next 64 bytes block */
		for (i = block_no * 64, j = 0; j < 64; i++, j++) {
			block[j] = text[i];
		}

		/* initialize the words for this iteration */
		unsigned int A = a0, B = b0, C = c0, D = d0;

	        /* breaking the modified message into 16 4 byte chunks.
	         * again, big endian ordering has been maintained */
		for (i = 0, j = 0; i < 16; i++, j += 4) {
			chunks[i] = ((block[j] << 24) | (block[j + 1] << 16) | 
				(block[j + 2]  << 8) | (block[j + 3]));
		}

		/* do the transformations on current hash words */
		for (i = 0; i < 64; i++) {
			unsigned int f, g;

			if (i >= 0 && i <= 15) {
				f = (B & C) | ((~B) & D);
				g = i;
			} 
			if (i >= 16 && i <= 31) {
				f = (D & B) | ((~D) & C);
				g = (5 * i + 1) % 16;
			}
			if (i >= 32 && i <= 47) {
				f = B ^ C ^ D;
				g = (3 * i + 5) % 16;
			}
			if (i >= 48 && i <= 63) {
				f = C ^ (B | (~D));
				g = (7 * i) % 16;
			}

			f = f + A + Constants[i] + chunks[g];
			A = D;
			D = C;
			C = B;
			B = B + ROTL(f, rotations[i]);
		}

		/* add this chunk's hash so far */
		a0 += A;
		b0 += B;
		c0 += C;
		d0 += D;

		block_no += 1;
	}

	/* append all the words into a single hash string */
	output[0]  = (a0 >> 24) & 0xFF; 
	output[1]  = (a0 >> 16) & 0xFF;
	output[2]  = (a0 >>  8) & 0xFF;
	output[3]  = (a0)       & 0xFF;

	output[4]  = (b0 >> 24) & 0xFF;
	output[5]  = (b0 >> 16) & 0xFF;
	output[6]  = (b0 >>  8) & 0xFF;
	output[7]  = (b0)       & 0xFF;

	output[8]  = (c0 >> 24) & 0xFF; 
	output[9]  = (c0 >> 16) & 0xFF;
	output[10] = (c0 >>  8) & 0xFF;
	output[11] = (c0)       & 0xFF;

	output[12] = (d0 >> 24) & 0xFF;
	output[13] = (d0 >> 16) & 0xFF;
	output[14] = (d0 >>  8) & 0xFF;
	output[15] = (d0)       & 0xFF;
}

void
add_padding(unsigned char *padded, 
            unsigned long long int size, 
            const unsigned long long int sizeof_hash)
{	
	padded[size] = 0x80;
	/* append the sizeof original string at the end of the padded string.
	 * big endian ordering has been maintained */
	padded[sizeof_hash - 8] = (size >> 56) & 0xFF;
	padded[sizeof_hash - 7] = (size >> 48) & 0xFF;
	padded[sizeof_hash - 6] = (size >> 40) & 0xFF;
	padded[sizeof_hash - 5] = (size >> 32) & 0xFF;
	padded[sizeof_hash - 4] = (size >> 24) & 0xFF;
	padded[sizeof_hash - 3] = (size >> 16) & 0xFF;
	padded[sizeof_hash - 2] = (size >>  8) & 0xFF;
	padded[sizeof_hash - 1] = (size)       & 0xFF;
}

int main(int argc, const char *argv[])
{
	const unsigned long long int size = strlen(argv[1]);
	unsigned long long int sizeof_hash = ceil(size / 64.0) * 64;
	unsigned int block_count, index = 0;

	if (size == 64) sizeof_hash += 64;
	if (size == 0) sizeof_hash = 64;

	unsigned char *padded = malloc(sizeof *padded * sizeof_hash);
	unsigned char digest[16];

	block_count = sizeof_hash / 64;	

	strncpy(padded, argv[1], size);
	add_padding(padded, size, sizeof_hash);
	MD5_engine(padded, block_count, digest);

	index = 0;
	while (index < 16) {
		printf("%x", digest[index]);
		index += 1;
	}
	printf("\n");
}
