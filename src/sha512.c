#include "ft_ssl.h"

unsigned long KKK[] = {
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
	0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
	0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
	0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
	0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
	0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
	0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
	0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
	0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
	0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
	0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

void sha512InitHash(t_hash *hash) {
	hash->HH0 = 0x6a09e667f3bcc908;
	hash->HH1 = 0xbb67ae8584caa73b;
	hash->HH2 = 0x3c6ef372fe94f82b;
	hash->HH3 = 0xa54ff53a5f1d36f1;
	hash->HH4 = 0x510e527fade682d1;
	hash->HH5 = 0x9b05688c2b3e6c1f;
	hash->HH6 = 0x1f83d9abfb41bd6b;
	hash->HH7 = 0x5be0cd19137e2179;
}

extern int isDebug;

void sha512Padding(unsigned char *message, size_t full_len, t_hash *hash) {
	size_t end = full_len % 128;

	message[end] = 0x80;
	if (end >= 112) {
		sha512EncodeBloc(hash, (unsigned long*)message);
		ft_bzero(message, 128);
	} else {
		ft_bzero(message + end + 1, 128 - end - 1);
	}
	full_len *= 8;
	full_len = swap64(full_len);
	ft_memcpy(message + 120, &full_len, 8); // peut etre 112
	sha512EncodeBloc(hash, (unsigned long*)message);
}

// &  (bitwise AND)
// |  (bitwise OR)
// ^  (bitwise XOR)
// << (left shift)
// >> (right shift)
// ~  (bitwise NOT)
void sha512EncodeBloc(t_hash *hash, void *data) {
	unsigned long A = hash->HH0;
	unsigned long B = hash->HH1;
	unsigned long C = hash->HH2;
	unsigned long D = hash->HH3;
	unsigned long E = hash->HH4;
	unsigned long F = hash->HH5;
	unsigned long G = hash->HH6;
	unsigned long H = hash->HH7;
	unsigned long S0, S1, temp1, temp2, CH, maj;
	unsigned long *W = (unsigned long *)data;
	unsigned long message[80];

	if (isDebug) ft_printf("\n=========== SHA ENCODE ===========\n");
	if (isDebug) sha512PrintHash(hash);
	for (unsigned long index = 0; index < 16; index++) {
		message[index] = swap64(W[index]);
	}
	ft_bzero(message + 16, 192);
	for (unsigned long index = 16; index < 80; index++) {
		S0 = rightRotate64(message[index - 15], 1) ^ rightRotate64(message[index - 15], 8) ^ (message[index - 15] >> 7);
		S1 = rightRotate64(message[index - 2], 19) ^ rightRotate64(message[index - 2], 61) ^ (message[index - 2]  >> 6);
		message[index] = message[index - 16] + S0 + message[index - 7] + S1;
	}
	print_bits((unsigned char *)message, 128);

	for (unsigned long index = 0; index < 80; index++) {
		S1 = rightRotate64(E, 14) ^ rightRotate64(E, 18) ^ rightRotate64(E, 41);
		CH = (E & F) ^ ((~E) & G);
		temp1 = H + S1 + CH + KKK[index] + message[index];
		S0 = rightRotate64(A, 28) ^ rightRotate64(A, 34) ^ rightRotate64(A, 39);
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
	hash->HH0 += A;
	hash->HH1 += B;
	hash->HH2 += C;
	hash->HH3 += D;
	hash->HH4 += E;
	hash->HH5 += F;
	hash->HH6 += G;
	hash->HH7 += H;
	if (isDebug) ft_printf("=========== END ENCODE ===========\n");
}

void sha512PrintHash(t_hash *hash) {
	ft_printf("%016lx%016lx%016lx%016lx%016lx%016lx%016lx%016lx",
		hash->HH0,
		hash->HH1,
		hash->HH2,
		hash->HH3,
		hash->HH4,
		hash->HH5,
		hash->HH6,
		hash->HH7
	);
}