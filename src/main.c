#include "ft_ssl.h"
#include "libft.h"

void usage() {
	ft_printf("Usage: ./ft_ssl [ALGO] -pqrsv\n");
	ft_printf("\nMessage Digest commands: \n");
	ft_printf("md5 sha224 sha224 sha256 sha384 sha512\n");
	exit(1);
}

int main(int argc, char **argv) {
	if (argc > 1) {
		if (!ft_strcmp(argv[1], "md5")) {
			md5Router(argv + 2);
		} else if (!ft_strcmp(argv[1], "sha224")) {
			sha224Router(argv + 2);
		} else if (!ft_strcmp(argv[1], "sha256")) {
			sha256Router(argv + 2);
		} else if (!ft_strcmp(argv[1], "sha384")) {
			sha384Router(argv + 2);
		} else if (!ft_strcmp(argv[1], "sha512")) {
			sha512Router(argv + 2);
		} else {
			usage();
		}
	} else {
		usage();
	}
}