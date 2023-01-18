#include "libft.h"
#include "ft_ssl.h"

unsigned long encode_decodeECB(t_des *des, unsigned long data, unsigned long *keys) {
	(void)des;
	return (desEncrypt(data, keys));
}

unsigned long encode_decode3ECB(t_des *des, unsigned long data, unsigned long *keys) {
	(void)des;
	return (desEncrypt(desEncrypt(desEncrypt(data, keys), keys), keys));
}