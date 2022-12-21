#include "ft_ssl.h"
#include "libft.h"
#include <sys/stat.h>
#include <fcntl.h> 

void shaGetFd(int fd, t_hash *hash) {
	size_t len;
	size_t size = 0;
	unsigned char input[64];
	unsigned char buffer[64];

	bzero(input, 64);
	while ((len = read(fd, buffer, 64)) > 0) {
		if ((size % 64) + len >= 64) {
			ft_memcpy(input + (size % 64), buffer, 64 - (size % 64));
			shaEncode512Bloc(hash, (unsigned int *)input);
			bzero(input, 64);
			ft_memcpy(input, buffer + (64 - (size % 64)), len - (64 - (size % 64)));
		} else {
			ft_memcpy(input + (size % 64), buffer, len);
		}
		size += len;
	}
	if (size % 64 > 56) {
		shaEncode512Bloc(hash, (unsigned int *)input);
	}
	padding(input, size);
	print_bits(input, 64);
	shaEncode512Bloc(hash, (unsigned int *)input);
}

void shaGetArg(char *message, t_hash *hash) {
	size_t	len = ft_strlen(message);
	size_t	index = 0;
	unsigned char	current[64];

	while (len - index >= 64) {
		shaEncode512Bloc(hash, (unsigned int*)message);
		message += 64;
		index += 64;
	}
	bzero(current, 64);
	ft_memcpy(current, message, len - index);
	if (len - index > 56) {
		shaEncode512Bloc(hash, (unsigned int *)current);
	}
	padding(current, len - index);
	shaEncode512Bloc(hash, (unsigned int *)current);
}

int sha256Router(char **argv) {
	char	*message = NULL;
	t_optpars opt;
	t_hash	hash;

	options(argv, &message, &opt);
	shaInitHash(&hash);
	shaGetFd(0, &hash);
	shaPrintHash(&hash);
	return 0;
}