#include "ft_ssl.h"
#include "libft.h"
#include <fcntl.h>

char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

extern int isDebug;

// TODO: Check == decode

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
	if (car == '=') return (0);
	ft_dprintf(2, "Base64: invalid input 1\n");
	exit(1);
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

void	base64EncodeBloc(unsigned char *message, int size, int fd) {
	unsigned int tmp;
	unsigned char *current;
	unsigned char lol;

	bzero((unsigned char *)&tmp, 4);
	ft_memcpy(&tmp, message, size);
	current = (unsigned char*)&tmp;
	for (int i = 0; i < size + 1; i++) {
		lol = *current & 0xFC;
		lol = lol >> 2;
		ft_dprintf(fd, "%c", getBase64(lol));
		tmp = turboShift(tmp);
	}
}

void	base64Encode(unsigned char *message, size_t size, int fd) {
	unsigned int index = 0;

	for (; index < (unsigned int)size - size % 3; index += 3) {
		base64EncodeBloc(message + index, 3, fd);
	}
	if (size % 3) {
		base64EncodeBloc(message + index, size % 3, fd);
		for (int i = 0; i < (3 - size % 3); i++) {
			ft_dprintf(fd, "=");
		}
	}
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

size_t	base64Decode(unsigned char *message, size_t size, char *output) {
	unsigned int index = 0, indexO = 0;
	int isEnd = 0;

	for (; index < (unsigned int)size - size % 4; index += 4) {
		int i = 0;
		for (; i < 4; i++) {
			if (isEnd == 2 || (isEnd > 0 && message[index + i] != '=')) {
				ft_dprintf(2, "Base64: invalid input 2\n");
				exit(1);
			}
			if (message[index + i] == '=') isEnd++;
			output[indexO + i] = getIndex(message[index + i]);
		}
		compressBase64(output + indexO);
		indexO += i - 1 - isEnd;
	}
	return indexO;
}

void	routerBase64(char **argv) {
	char *input = NULL, *output = NULL;
	t_optpars	opt;
	char	data[120];
	ssize_t len;
	size_t nlen;
	int fdi = 0, fdo = 1;

	optionsBase64(argv, &input, &output, &opt);
	if (input) {
		if ((fdi = open(input, O_RDONLY)) < 0) {
			ft_dprintf(2, "ERROR: Can't open file `%s'\n", input);
			exit(1);
		}
	}
	if (output) {
		if ((fdo = open(output, O_WRONLY | O_CREAT)) < 0) { // Fichier existe deja
			ft_dprintf(2, "ERROR: Can't open file `%s'\n", output);
			exit(1);
		}
	}
	while ((len = turboRead(fdi, data, 120, ft_tabfind(opt.opt, "-d"))) > 0) {
		if (ft_tabfind(opt.opt, "-d")) {
			if (len % 4) {
				ft_dprintf(2, "Base64: invalid input 3\n");
				exit(1);
			}
			nlen = base64Decode(data, len, data);
			write(fdo, data, nlen);
		} else {
			base64Encode(data, len, fdo);
		}
		if (len != 120) return ;
	}
	// ft_dprintf(fdo, "\n");
	close(fdi);
	close(fdo);
}
