#include "libft.h"
#include "ft_ssl.h"

unsigned long encode_decodeECB(t_des *des, unsigned long data, unsigned long *keys) {
	return (desEncrypt(data, keys));
}