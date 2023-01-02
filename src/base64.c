#include "ft_ssl.h"
#include "libft.h"

char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

extern int isDebug;

void optionsBase64(char **argv, char **input, char **output, t_optpars *optpars) {
	t_opt	*opt;
	unsigned char ret;

	ft_bzero(optpars, sizeof(t_optpars));
	opt_init(&opt);
	opt_addvar2(&opt, "-i", (void*)input, OPT_STR);
	opt_addvar2(&opt, "-o", (void*)output, OPT_STR);
	opt_addvar(&opt, "-d", NULL, 0);
	opt_addvar(&opt, "-e", NULL, 0);
	opt_addvar(&opt, "-v", NULL, 0);
	ret = opt_parser(opt, argv, optpars, "ft_ssl");
	opt_free(&opt);
	if (ret)
		exit(ret);
	isDebug = ft_tabfind(optpars->opt, "-v") > 0;
}

void	base64Router(char **argv)
char	getBase64(char index) {
	return base64[index];
}

unsigned char	getIndex(char car) {
	for (unsigned char index = 0; base64[index]; index++) {
		if (base64[index] == car) {
			// ft_printf("%d\n", index);
			return (index);
		}
	}
	return 0;
}

unsigned int	turboShift(unsigned int n) {
	char *tmp = (unsigned char*)&n;

	tmp[0] = tmp[0] << 6;
	tmp[0] |= (tmp[1] >> 2) & 0x3F;
	tmp[1] = tmp[1] << 6;
	tmp[1] |= (tmp[2] >> 2) & 0x3F;
	tmp[2] = tmp[2] << 6;
	tmp[2] |= (tmp[3] >> 2) & 0x3F;
	return n;
}

void	base64EncodeBloc(unsigned char *message, int size) {
	unsigned int tmp;
	unsigned char *current;
	unsigned char lol;

	bzero((unsigned char *)&tmp, 4);
	ft_memcpy(&tmp, message, size);
	current = (unsigned char*)&tmp;
	for (int i = 0; i < size + 1; i++) {
		lol = *current & 0xFC;
		lol = lol >> 2;
		ft_printf("%c", getBase64(lol));
		tmp = turboShift(tmp);
	}
}

void	base64Encode(unsigned char *message, size_t size) {
	unsigned int index = 0;
	isDebug = 1;

	for (; index < (unsigned int)size - size % 3; index += 3) {
		base64EncodeBloc(message + index, 3);
	}
	if (size % 3) {
		base64EncodeBloc(message + index, size % 3);
		for (int i = 0; i < (3 - size % 3); i++) {
			ft_printf("=");
		}
	}
	ft_printf("\n");
}

void	compressBase64(char *str) {
	str[0] = str[0] << 2;
	str[0] |= (str[1] >> 4) & 0x3;

	str[1] = str[1] << 4;
	str[1] |= (str[2] >> 2) & 0xF;

	str[2] = str[2] << 6;
	str[2] |= str[3];

	str[3] = 0;
}

void	base64Decode(unsigned char *message, size_t size) {
	unsigned int index = 0;
	unsigned char tmp[4];
	isDebug = 1;

	for (; index < (unsigned int)size - size % 4; index += 4) {
		bzero(tmp, 4);
		for (int i = 0; i < 4; i++) {
			tmp[i] = getIndex(message[index + i]);
		}
		// print_bits(tmp, 4);
		compressBase64(tmp);
		// print_bits(tmp, 4);
		write(1, tmp, 3);
	}
	ft_printf("\n");
}