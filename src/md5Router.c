#include "ft_ssl.h"
#include "libft.h"
#include <fcntl.h> 

void md5GetFd(int fd, t_hash *hash, int isPrint) {
	ssize_t len;
	size_t size = 0;
	unsigned char input[64];
	unsigned char buffer[64];

	md5InitHash(hash);
	ft_bzero(input, 64);
	while ((len = read(fd, buffer, 64)) > 0) {
		if (isPrint) write(1, buffer, len);
		if ((size % 64) + len >= 64) {
			ft_memcpy(input + (size % 64), buffer, 64 - (size % 64));
			md5EncodeBloc(hash, (unsigned int *)input);
			ft_bzero(input, 64);
			ft_memcpy(input, buffer + (64 - (size % 64)), len - (64 - (size % 64)));
		} else {
			ft_memcpy(input + (size % 64), buffer, len);
		}
		size += len;
	}
	if (len == -1) {
		ft_dprintf(2, "ERROR: Failed read file\n");
		exit(1);
	}
	md5Padding(input, size, hash);
}

void md5GetArg(char *message, t_hash *hash) {
	size_t	len = ft_strlen(message);
	size_t	index = 0;
	unsigned char	current[64];

	md5InitHash(hash);
	while (len - index >= 64) {
		md5EncodeBloc(hash, (unsigned int*)message);
		message += 64;
		index += 64;
	}
	ft_bzero(current, 64);
	ft_memcpy(current, message, len - index);
	md5Padding(current, len, hash);
}

void md5Router(char **argv) {
	router(argv, "MD5", &md5GetFd, &md5GetArg, &md5PrintHash);
}