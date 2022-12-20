#include "ft_ssl.h"
#include "libft.h"
#include <sys/stat.h>
#include <fcntl.h> 

void getFd(int fd, t_hash *hash) {
	size_t len;
	size_t size = 0;
	unsigned char input[64];
	unsigned char buffer[64];

	bzero(input, 64);
	while ((len = read(fd, buffer, 64)) > 0) {
		if ((size % 64) + len >= 64) {
			ft_memcpy(input + (size % 64), buffer, 64 - (size % 64));
			encode512bloc(hash, (unsigned int *)input);
			bzero(input, 64);
			ft_memcpy(input, buffer + (64 - (size % 64)), len - (64 - (size % 64)));
		} else {
			ft_memcpy(input + (size % 64), buffer, len);
		}
		size += len;
	}
	if (size % 64 > 56) {
		encode512bloc(hash, (unsigned int *)input);
	}
	padding(input, size);
	print_bits(input, 64);
	encode512bloc(hash, (unsigned int *)input);
}

void getArg(char *message, t_hash *hash) {
	size_t	len = ft_strlen(message);
	size_t	index = 0;
	unsigned char	current[64];

	while (len - index >= 64) {
		encode512bloc(hash, (unsigned int*)message);
		message += 64;
		index += 64;
	}
	bzero(current, 64);
	ft_memcpy(current, message, len - index);
	if (len - index > 56) {
		encode512bloc(hash, (unsigned int *)current);
	}
	padding(current, len - index);
	encode512bloc(hash, (unsigned int *)current);
}

int md5Router(char **argv) {
	char	*message = NULL;
	t_optpars opt;
	t_hash	hash;

	options(argv, &message, &opt);
	initHash(&hash);
	ft_printf("File: %p\n", opt.arg[0]);
	ft_printf("Message: %p\n", message);
	if (message) {
		getArg(message, &hash);
	} else {
		int fd = 0;
		if (opt.arg && opt.arg[0]) {
			if ((fd = open(opt.arg[0], O_RDONLY)) < 0) {
				ft_dprintf(2, "ERROR: Can't open file `%s'\n", opt.arg[0]);
				exit(1);
			}
		}
		ft_printf("%d\n", fd);
		getFd(fd, &hash);
	}
	if (!ft_tabfind(opt.opt, "-q")) {
		printHash(&hash);
	}
	return 0;
}
