#include "ft_ssl.h"
#include "libft.h"
#include <sys/stat.h>
#include <fcntl.h> 

void sha256GetFd(int fd, t_hash *hash, int isPrint) {
	size_t len;
	size_t size = 0;
	unsigned char input[64];
	unsigned char buffer[64];

	sha256InitHash(hash);
	bzero(input, 64);
	while ((len = read(fd, buffer, 64)) > 0) {
		if (isPrint) write(1, buffer, len);
		if ((size % 64) + len >= 64) {
			ft_memcpy(input + (size % 64), buffer, 64 - (size % 64));
			sha256EncodeBloc(hash, (unsigned int *)input);
			bzero(input, 64);
			ft_memcpy(input, buffer + (64 - (size % 64)), len - (64 - (size % 64)));
		} else {
			ft_memcpy(input + (size % 64), buffer, len);
		}
		size += len;
	}
	sha256Padding(input, size, hash);
}

void sha256GetArg(char *message, t_hash *hash) {
	size_t	len = ft_strlen(message);
	size_t	index = 0;
	unsigned char	current[64];

	sha256InitHash(hash);
	while (len - index >= 64) {
		sha256EncodeBloc(hash, (unsigned int*)message);
		message += 64;
		index += 64;
	}
	bzero(current, 64);
	ft_memcpy(current, message, len - index);
	sha256Padding(current, len, hash);
}

int sha256Router(char **argv) {
	return (router(argv, "SHA256", &sha256GetFd, &sha256GetArg, &sha256PrintHash));
}