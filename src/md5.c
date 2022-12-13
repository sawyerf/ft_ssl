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

// &  (bitwise AND)
// |  (bitwise OR)
// ^  (bitwise XOR)
// << (left shift)
// >> (right shift)
// ~  (bitwise NOT)
void encode512bloc(t_512bloc *bloc, unsigned long *message) {
	unsigned long A = bloc->A;
	unsigned long B = bloc->B;
	unsigned long C = bloc->C;
	unsigned long D = bloc->D;
	unsigned long F = 0;
	unsigned long G = 0;
	unsigned long temp = 0;

	for (int index = 0; i < 64; i++) {
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
		B = LEFT_ROTATE((A + F + entier[index], message[G]), R[index]) + B;
		A = temp;
	}
	bloc->A += A;
	bloc->B += B;
	bloc->C += C;
	bloc->D += D;
}

void padding(unsigned char *message, size_t len) {
	size_t add = len * 8 % 512;
	if (add < 448) {
		add = 448 - add;
	} else {
		add = 512 - add + 448;
	}
	add /= 8;
	message[len] = 0x80;
	for (size_t i = 1; i < add + 8; i++) {
		message[len + i] = 0x00;
	}
	message[len + add] = len * 8;
	// print_bits(message, len + add + 8);
	print_bits(message + add + len - 64, 64);
}

long *ft_md5(unsigned char *message, size_t len) {
	(void)len;
	// print_bits(message, len);
	padding(message, len);
	return NULL;
}