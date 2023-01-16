#include "ft_ssl.h"

extern t_router routesHash[];

void pbkdf2(char *password, unsigned long salt, t_hash *hash) {
	t_router *route = routesHash + 4; // sha512
	size_t	lenPass = ft_strlen(password);
	char	*concat = malloc(lenPass + 8*8 + 4 + 1);
	unsigned index = 1;

	ft_bzero(hash, sizeof(t_hash));
	ft_memcpy(concat, &salt, 8);
	ft_memcpy(concat + 8, &index, 4);
	ft_strcpy(concat + 8 + 4, password);
	getArg(concat, lenPass + 3, hash, route);

	ft_strcpy(concat + 8*8 + 4, password);
	for (index = 2; index <= 1000; index++) {
		ft_memcpy(concat, &hash->H0, 8*8);
		ft_memcpy(concat + 8*8, &index, 4);
		getArg(concat, lenPass + 8*8 + 4, hash, route);
	}
	free(concat);
}