#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define F(x, y, z) ((x & y) | (~(x) & z))
#define G(x, y, z) ((x & y) | (y & ~(z)))
#define H(x, y, z) (x ^ y ^ z)
#define I(x, y, z) (y ^ (x | ~(z)))
#define ROTL(x, n) ((x << n) | (x >> (32 - n)))

void
add_padding(unsigned char *text, unsigned long long int size, int zeroes)
{
	int index = 1, factor = 1;
	
	text[size] = 0x01;
	while (index < zeroes) {
		text[size + index] = 0x00;
		index += 1;
	}
	
	index = 0;
	text[63 - index] = 0xFF & size;
	index += 1;
	while (factor < 8) {
		text[63 - index] = 0xFF & (size >> (8 * factor));
		index += 1;
		factor += 1;
	}
	return;
}

void
create_MD5_digest(const unsigned char *text, unsigned char *digest)
{

	/* this is just floor(2^32 * abs(sin(i + 1)), where i is from 0 to 63 */
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
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,7, 12, 17, 22,
		5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
	};

	/* first four initial constants of the digest */
	unsigned int A = 0x67452301,  B = 0xefcdab89, C = 0x98badcfe,
	             D = 0x10325476, i, j;
	unsigned int chunks[16];
	unsigned int AA = A, BB = B, CC = C, DD = D;

	/* breaking the modified message into 16 4 byte chunks */
	for (i = 0, j = 0; i < 16 && j < 64; i++, j += 4) {
		chunks[i] = text[j] | text[j + 1] | text[j + 2] | text[j + 3];
	}
	
	for (i = 0; i < 64; i++) {
		unsigned int f, g;

		if (i >= 0 && i <= 15) {
			f = F(B, C, D);
			g = i;
		} 
		else if (i >= 16 && i <= 31) {
			f = G(B, C, D);
			g = (5 * i + 1) % 16;
		}
		else if (i >= 32 && i <= 47) {
			f = H(B, C, D);
			g = (3 * i + 5) % 16;
		}
		else {
			f = I(B, C, D);
			g = (7 * i) % 16;
		}

		f = f + AA + Constants[i] + chunks[g];
		AA = DD;
		DD = CC;
		CC = BB;
		BB = BB + ROTL(f, rotations[i]);
	}

	/* add this chunk's hash so far (in case of multiple chunks) */
	A += AA;
	B += BB;
	C += CC;
	D += DD;

	printf("%x %x %x %x\n", A, B, C, D);

	digest[0]  = (A >> 24) & 0xFF;
	digest[1]  = (A >> 16) & 0xFF;
	digest[2]  = (A >> 8) & 0xFF;
	digest[3]  = A & 0xFF;

	digest[4]  = (B >> 24) & 0xFF;
	digest[5]  = (B >> 16) & 0xFF;
	digest[6]  = (B >> 8) & 0xFF;
	digest[7]  = B & 0xFF;
	
	digest[8]  = (C >> 24) & 0xFF;
	digest[9]  = (C >> 16) & 0xFF;
	digest[10] = (C >> 8) & 0xFF;
	digest[11] = C & 0xFF;
	
	digest[12] = (D >> 24) & 0xFF;
	digest[13] = (D >> 16) & 0xFF;
	digest[14] = (D >> 8) & 0xFF;
	digest[15] = D & 0xFF;
}

void
print(const unsigned char *string, int size)
{
	printf("\n");
	int index = 0;
	while (index < size) {
		printf("%x", string[index]);
		index += 1;
	}
	printf("\n");
	return;
}

int main(int argc, char *argv[])
{
	/* parse 64 bytes at a time when dealing with strlen(plainetxt) >= 512
	 */
	unsigned char *plaintext = "Enter your string here :)";
	unsigned char digest[16];
	unsigned char ciphertext[64];
	unsigned long long int sizeof_plaintext = strlen(plaintext);
	int zeroes = 56 - sizeof_plaintext - 1;

	strncpy(ciphertext, plaintext, sizeof_plaintext);
	
	/* 1), 2) append a 1, some 0s and the sizeof plaintext in the end */
	add_padding(ciphertext, sizeof_plaintext, zeroes);
	
	/* 3) initialize the MD buffer and do the transformations */
	create_MD5_digest(ciphertext, digest);

	/* 5) Output the hashed message */
	print(digest, 16);
	
	return 0;
}

