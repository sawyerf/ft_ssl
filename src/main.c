#include "ft_ssl.h"
#include "libft.h"

void usage() {
	ft_printf("Usage: ./ft_ssl [ALGO] -pqrs\n");
	exit(1);
}

int main(int argc, char **argv) {
	if (argc > 1) {
		if (!ft_strcmp(argv[1], "md5")) {
			md5Router(argv + 2);
		} else if (!ft_strcmp(argv[1], "sha256")) {
			sha256Router(argv + 2);
		}
	} else {
		usage();
	}
}