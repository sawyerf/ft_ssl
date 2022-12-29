#include "ft_ssl.h"
#include "libft.h"

char base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base6Encode(unsigned char *message, size_t size) {
	unsigned int tmp;

	for (int index = 3; index < size; index += 3) {
		tmp = (unsigned int)message[index] & 0xFF000000;
		print_bits(tmp, 4);
	}
}