#include "ft_ssl.h"

int isDebug = 1;

void print_bit(unsigned char n) {
	for (int i = 7; i >= 0; i--) {
		ft_printf("%d", (n >> i) & 1);
	}
	ft_printf(" ");
}

void print_bits(void *str, size_t len) {
	if (!isDebug) return ;
	for (size_t i = 0; i < len; i++) {
		if (!(i % 8)) ft_printf("\n");
		print_bit(((unsigned char *)str)[i]);
	}
	ft_printf("\n");
}

void print_dbits(char *name, void *str, size_t len) {
	ft_printf("%s: \n", name);
	for (size_t i = 0; i < len; i++) {
		if (!(i % 8) && i) ft_printf("\n");
		print_bit(((unsigned char *)str)[i]);
	}
	ft_printf("\n");
}
void options(char **argv, char **message, t_optpars *optpars) {
	t_opt	*opt;
	unsigned char ret;

	ft_bzero(optpars, sizeof(t_optpars));
	opt_init(&opt);
	opt_addvar2(&opt, "-s", (void*)message, OPT_STR);
	opt_addvar(&opt, "-q", NULL, 0);
	opt_addvar(&opt, "-r", NULL, 0);
	opt_addvar(&opt, "-p", NULL, 0);
	opt_addvar(&opt, "-v", NULL, 0);
	ret = opt_parser(opt, argv, optpars, "ft_ssl");
	opt_free(&opt);
	if (ret)
		exit(ret);
	isDebug = ft_tabfind(optpars->opt, "-v") > 0;
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

unsigned int leftRotate(unsigned int n, unsigned int d)
{
	return (n << d)|(n >> (32 - d));
}

unsigned int rightRotate(unsigned int n, unsigned int d) {
	return (n >> d) | (n << (32 - d));
}

unsigned long rightRotate64(unsigned long n, unsigned long d) {
	return (n >> d) | (n << (64 - d));
}

unsigned int rightShift(unsigned int n, unsigned int d) {
	return (n >> d);
}

ssize_t turboRead(int fd, char *data, size_t sizeBloc) {
	unsigned char buffer[128];
	ssize_t len;
	size_t size = 0;

	ft_bzero(data, sizeBloc);
	while ((len = read(fd, data + size, sizeBloc - size)) > 0) {
		size += len;
		if (size == sizeBloc) {
			return (size);
		}
	}
	if (len < 0) {
		return -1;
	}
	return size;
}

void	turboNShift(void *n, int size) {
	unsigned char *tmp = (unsigned char*)n;
	int index;

	for (index = 0; index < size - 1; index++) {
		tmp[index] = tmp[index] << 6;
		tmp[index] |= (tmp[index + 1] >> 2) & 0x3F;
	}
	tmp[index + 1] = tmp[index + 1] << 6;
}

unsigned long	atoi_hex(char *str)
{
	unsigned long	ret;

	ret = 0;
	for (int i = 0; str[i]; i++)
	{
		if (str[i] >= '0' && str[i] <= '9')
			ret = ret * 16 + str[i] - '0';
		else if (str[i] >= 'a' && str[i] <= 'f')
			ret = ret * 16 + str[i] - 'a' + 10;
		else if (str[i] >= 'A' && str[i] <= 'F')
			ret = ret * 16 + str[i] - 'A' + 10;
		else
			return (-1);
	}
	return (ret);
}