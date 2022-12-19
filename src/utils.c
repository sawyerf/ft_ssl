#include "ft_ssl.h"
#include <stdio.h>

void print_bit(unsigned char n) {
	for (int i = 7; i >= 0; i--) {
		ft_printf("%d", (n >> i) & 1);
	}
	ft_printf(" ");
}

void print_bits(unsigned char *str, size_t len) {
	ft_printf("len: %zu\n", len);
	for (size_t i = 0; i < len; i++) {
		print_bit(str[i]);
	}
	ft_printf("\n");
}
