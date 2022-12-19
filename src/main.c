#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ft_ssl.h"

void getstdin() {
	size_t len;
	size_t size = 0;
	unsigned char input[64];
	unsigned char buffer[64];
	t_hash hash;

	initHash(&hash);
	bzero(input, 64);
	while ((len = read(0, buffer, 64)) > 0) {
		if ((size % 64) + len >= 64) {
			ft_memcpy(input + (size % 64), buffer, 64 - (size % 64));
			encode512bloc(&hash, (unsigned int *)input);
			bzero(input, 64);
			ft_memcpy(input, buffer + (64 - (size % 64)), len - (64 - (size % 64)));
		} else {
			ft_memcpy(input + (size % 64), buffer, len);
		}
		size += len;
	}
	if (size % 64 > 56) {
		encode512bloc(&hash, (unsigned int *)input);
	}
	padding(input, size);
	encode512bloc(&hash, (unsigned int *)input);
	printHash(&hash);
}

int main(int argc, char *argv[]) {
	getstdin();
	return 0;
}