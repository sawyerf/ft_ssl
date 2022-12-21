#include "ft_ssl.h"
#include <stdio.h>

void print_bit(unsigned char n) {
	for (int i = 7; i >= 0; i--) {
		ft_printf("%d", (n >> i) & 1);
	}
	ft_printf(" ");
}

void print_bits(unsigned char *str, size_t len) {
	for (size_t i = 0; i < len; i++) {
		print_bit(str[i]);
	}
	ft_printf("\n");
}

int options(char **argv, char **message, t_optpars *ret) {
	t_opt	*opt;

	bzero(ret, sizeof(t_optpars));
	opt_init(&opt);
	opt_addvar2(&opt, "-s", (void*)message, OPT_STR);
	opt_addvar(&opt, "-q", NULL, 0);
	opt_addvar(&opt, "-r", NULL, 0);
	opt_addvar(&opt, "-p", NULL, 0);
	opt_parser(opt, argv, ret, "ft_ssl");
	opt_free(&opt);
}

unsigned int swap32(unsigned int num) {
	return ((num>>24)&0xff) | // move byte 3 to byte 0
        ((num<<8)&0xff0000) | // move byte 1 to byte 2
        ((num>>8)&0xff00) | // move byte 2 to byte 1
        ((num<<24)&0xff000000); // byte 0 to byte 3
}

size_t swap64(size_t val)
{
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL ) | ((val >> 8) & 0x00FF00FF00FF00FFULL );
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL ) | ((val >> 16) & 0x0000FFFF0000FFFFULL );
    return (val << 32) | (val >> 32);
}
