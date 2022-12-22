#include "ft_ssl.h"
#include <byteswap.h>

unsigned int KK[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2	
};

void sha256InitHash(t_hash *hash) {
	hash->H0 = 0x6a09e667;
	hash->H1 = 0xbb67ae85;
	hash->H2 = 0x3c6ef372;
	hash->H3 = 0xa54ff53a;
	hash->H4 = 0x510e527f;
	hash->H5 = 0x9b05688c;
	hash->H6 = 0x1f83d9ab;
	hash->H7 = 0x5be0cd19;
}

void sha256Padding(unsigned char *message, size_t full_len, t_hash *hash) {
	size_t end = full_len % 64;

	message[end] = 0x80;
	if (end >= 56) {
		sha256EncodeBloc(hash, (unsigned int*)message);
		bzero(message, 64);
	} else {
		bzero(message + end + 1, 64 - end - 1);
	}
	full_len *= 8;
	full_len = swap64(full_len);
	ft_memcpy(message + 56, &full_len, 8);
	sha256EncodeBloc(hash, (unsigned int*)message);
}

// &  (bitwise AND)
// |  (bitwise OR)
// ^  (bitwise XOR)
// << (left shift)
// >> (right shift)
// ~  (bitwise NOT)
void sha256EncodeBloc(t_hash *hash, unsigned int *W) {
	unsigned int A = hash->H0;
	unsigned int B = hash->H1;
	unsigned int C = hash->H2;
	unsigned int D = hash->H3;
	unsigned int E = hash->H4;
	unsigned int F = hash->H5;
	unsigned int G = hash->H6;
	unsigned int H = hash->H7;
	unsigned int S0, S1, temp1, temp2, CH, maj;
	unsigned int message[64];

	for (unsigned int index = 0; index < 16; index++) {
		message[index] = swap32(W[index]);
	}
	ft_bzero(message + 16, 192);
	for (unsigned int index = 16; index < 64; index++) {
		S0 = rightRotate(message[index - 15], 7) ^ rightRotate(message[index - 15], 18) ^ rightShift(message[index - 15], 3);
		S1 = rightRotate(message[index - 2], 17) ^ rightRotate(message[index - 2], 19) ^ rightShift(message[index - 2], 10);
		message[index] = message[index - 16] + S0 + message[index - 7] + S1;
	}

	for (unsigned int index = 0; index < 64; index++) {
		S1 = rightRotate(E, 6) ^ rightRotate(E, 11) ^ rightRotate(E, 25);
		CH = (E & F) ^ ((~E) & G);
		temp1 = H + S1 + CH + KK[index] + message[index];
		S0 = rightRotate(A, 2) ^ rightRotate(A,13) ^ rightRotate(A, 22);
		maj = (A & B) ^ (A & C) ^ (B & C);
		temp2 = S0 + maj;
 
		H = G;
		G = F;
		F = E;
		E = D + temp1;
		D = C;
		C = B;
		B = A;
		A = temp1 + temp2;
	}
	hash->H0 += A;
	hash->H1 += B;
	hash->H2 += C;
	hash->H3 += D;
	hash->H4 += E;
	hash->H5 += F;
	hash->H6 += G;
	hash->H7 += H;
}

void sha256PrintHash(t_hash *hash) {
	ft_printf("%08x%08x%08x%08x%08x%08x%08x%08x\n",
		hash->H0,
		hash->H1,
		hash->H2,
		hash->H3,
		hash->H4,
		hash->H5,
		hash->H6,
		hash->H7
	);
}