#include "ft_ssl.h"
#include "libft.h"
#include <sys/stat.h>
#include <fcntl.h> 

void sha384GetFd(int fd, t_hash64 *hash, int isPrint) {
	size_t len;
	size_t size = 0;
	unsigned char input[128];
	unsigned char buffer[128];

	sha384InitHash(hash);
	bzero(input, 128);
	while ((len = read(fd, buffer, 128)) > 0) {
		if (isPrint) write(1, buffer, len);
		if ((size % 128) + len >= 128) {
			ft_memcpy(input + (size % 128), buffer, 128 - (size % 128));
			sha512EncodeBloc(hash, (unsigned long *)input);
			bzero(input, 128);
			ft_memcpy(input, buffer + (128 - (size % 128)), len - (128 - (size % 128)));
		} else {
			ft_memcpy(input + (size % 128), buffer, len);
		}
		size += len;
	}
	sha512Padding(input, size, hash);
}

void sha384GetArg(char *message, t_hash64 *hash) {
	size_t	len = ft_strlen(message);
	size_t	index = 0;
	unsigned char	current[128];

	sha384InitHash(hash);
	while (len - index >= 128) {
		sha512EncodeBloc(hash, (unsigned long*)message);
		message += 128;
		index += 128;
	}
	bzero(current, 128);
	ft_memcpy(current, message, len - index);
	sha512Padding(current, len, hash);
}

int sha384Router(char **argv) {
	return (router64(argv, "SHA384", &sha384GetFd, &sha384GetArg, &sha384PrintHash));
}