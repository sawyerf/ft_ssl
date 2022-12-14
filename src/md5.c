#include "ft_ssl.h"
#include <stdio.h>

void print_bit(unsigned char n) {
	for (int i = 7; i >= 0; i--) {
		printf("%d", (n >> i) & 1);
	}
	printf(" ");
}
void print_bits(unsigned char *str, size_t len) {
	printf("len: %zu\n", len);
	for (size_t i = 0; i < len; i++) {
		print_bit(str[i]);
	}
	printf("\n");
}


unsigned int R[] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

unsigned int K[] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

void init_hash(t_hash *hash) {
	hash->H1 = 0x67452301;
	hash->H2 = 0xefcdab89;
	hash->H3 = 0x98badcfe;
	hash->H4 = 0x10325476;
}

int leftRotate(int n, unsigned int d)
{
	return (n << d)|(n >> (32 - d));
}

unsigned int toLittleEndian32(unsigned int num) {
	return ((num>>24)&0xff) | // move byte 3 to byte 0
        ((num<<8)&0xff0000) | // move byte 1 to byte 2
        ((num>>8)&0xff00) | // move byte 2 to byte 1
        ((num<<24)&0xff000000); // byte 0 to byte 3
}

void Array32ToLittleEndian(unsigned int *message, size_t size) {
	for (size_t index; index < size; index++) {
		message[index] = toLittleEndian32(message[index]);
	}
}

void padding(unsigned char *message, size_t full_len) {
	size_t end = full_len % 64;

	if (end > 56) {
		end = 0;
	}
	message[end] = 0x80;
	full_len *= 8;
	bzero(message + end + 1, 64 - end - 1);
	ft_memcpy(message + 56, &full_len, 8);
}

// &  (bitwise AND)
// |  (bitwise OR)
// ^  (bitwise XOR)
// << (left shift)
// >> (right shift)
// ~  (bitwise NOT)
void encode512bloc(t_hash *hash, unsigned int *message) {
	unsigned int A = hash->H1;
	unsigned int B = hash->H2;
	unsigned int C = hash->H3;
	unsigned int D = hash->H4;
	unsigned int F, G, temp = 0;

	Array32ToLittleEndian(message);
	print_bits((unsigned int*)message, 16);
	for (int index = 0; index < 64; index++) {
		if (0 <= index && index <= 15) {
			F = (B & C) | ((~B) & D);
			G = index;
		} else if (16 <= index && index <= 31) {
			F = (D & B) | ((~D) & C);
			G = (5 * index + 5) % 16;
		} else if (32 <= index && index <= 47) {
			F = B ^ C ^ D;
			G = (3 * index + 5) % 16;
		} else if (48 <= index && index <= 63) {
			F = C ^ (B | (~D));
			G = (7 * index) % 16;
		}
		temp = D;
		D = C;
		C = B;
		B = leftRotate((A + F + K[index], message[G]), R[index]) + B;
		A = temp;
	}
	hash->H1 += A;
	hash->H2 += B;
	hash->H3 += C;
	hash->H4 += D;
}

char *printHash(t_hash *hash) {
	for(unsigned int i = 0; i < 4; ++i){

	}
	printf("%08x%08x%08x%08x\n", hash->H1, hash->H2, hash->H3, hash->H4);
}

long *ft_md5(unsigned char *message, size_t len) {
	(void)len;
	// print_bits(message, len);
	padding(message, len);
	return NULL;
}