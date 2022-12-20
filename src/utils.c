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
