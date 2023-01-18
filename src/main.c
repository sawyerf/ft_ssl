#include "ft_ssl.h"
#include "libft.h"

void usage() {
	ft_printf("Usage: ./ft_ssl [ALGO] -pqrsv\n");
	ft_printf("\nMessage Digest commands: \n");
	ft_printf("md5 sha224 sha224 sha256 sha384 sha512\n");
	ft_printf("\nCipher commands:\n");
	ft_printf("base64 des des-ecb des-cbc des-cfb des-ctr des-ofb\n");

	ft_printf("\n---\n");
	ft_printf("\nMessage Digest options: \n");
	ft_printf("-p   echo STDIN to STDOUT and append the checksum to STDOUT\n");
	ft_printf("-q   quiet mode\n");
	ft_printf("-r   reverse the format of the output.\n");
	ft_printf("-s   print the sum of the given string\n");

	ft_printf("\nCipher options:\n");
	ft_printf("-a   decode/encode the input/output in base64, depending on the encrypt mode\n");
	ft_printf("-d   decrypt mode\n");
	ft_printf("-e   encrypt mode (default)\n");
	ft_printf("-i   input file for message\n");
	ft_printf("-k   key in hex is the next argument.\n");
	ft_printf("-o   output file for message\n");
	ft_printf("-p   password in ascii is the next argument.\n");
	ft_printf("-s   the salt in hex is the next argument.\n");
	ft_printf("-v   initialization vector in hex is the next argument.\n");

	exit(1);
}

int main(int argc, char **argv) {
	if (argc > 1) {
		if (getRouter(argv, argv[1])) {
			return (0);
		} else {
			ft_dprintf(2, "ft_ssl: Error: '%s' is an invalid command.\n", argv[1]);
			usage();
		}
	} else {
		usage();
	}
}