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
		t_router *route = getRouter(argv[1]);

		if (route) {
			router(argv + 2, route);
		} else {
			usage();
		}
	} else {
		usage();
	}
}