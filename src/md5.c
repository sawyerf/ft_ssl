#include "ft_ssl.h"
#include <stdio.h>

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

extern int isDebug;

void md5InitHash(t_hash *hash) {
	hash->H1 = 0x67452301;
	hash->H2 = 0xefcdab89;
	hash->H3 = 0x98badcfe;
	hash->H4 = 0x10325476;
}

void md5Padding(unsigned char *message, size_t full_len, t_hash *hash) {
	size_t end = full_len % 64;

	message[end] = 0x80;
	if (end >= 56) {
		md5EncodeBloc(hash, (unsigned int*)message);
		ft_bzero(message, 64);
	} else {
		ft_bzero(message + end + 1, 64 - end - 1);
	}
	full_len *= 8;
	ft_memcpy(message + 56, &full_len, 8);
	md5EncodeBloc(hash, (unsigned int*)message);
}

// &  (bitwise AND)
// |  (bitwise OR)
// ^  (bitwise XOR)
// << (left shift)
// >> (right shift)
// ~  (bitwise NOT)
void md5EncodeBloc(t_hash *hash, void *data) {
	unsigned int A = hash->H1;
	unsigned int B = hash->H2;
	unsigned int C = hash->H3;
	unsigned int D = hash->H4;
	unsigned int F = 0;
	unsigned int G = 0;
	unsigned int temp = 0;
	unsigned int *message = (unsigned int *)data;

	if (isDebug) ft_printf("\n=========== MD5 ENCODE ===========\n");
	if (isDebug) md5PrintHash(hash);
	print_bits((unsigned char *)message, 64);
	for (unsigned int index = 0; index < 64; index++) {
		if (index <= 15) {
			F = (B & C) | ((~B) & D);
			G = index;
		} else if (16 <= index && index <= 31) {
			F = (D & B) | ((~D) & C);
			G = (5 * index + 1) % 16;
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
		B = leftRotate(A + F + K[index] + message[G], R[index]) + B;
		A = temp;
	}
	hash->H1 += A;
	hash->H2 += B;
	hash->H3 += C;
	hash->H4 += D;
	if (isDebug) ft_printf("=========== END ENCODE ===========\n");
}

void md5PrintHash(t_hash *hash) {
	ft_printf("%08x%08x%08x%08x",
		swap32(hash->H1),
		swap32(hash->H2),
		swap32(hash->H3),
		swap32(hash->H4)
	);
}