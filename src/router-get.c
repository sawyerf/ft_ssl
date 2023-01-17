#include "ft_ssl.h"
#include "libft.h"

t_router routesHash[] = {
	{"md5",    "MD5",    64,  &md5InitHash, &md5EncodeBloc, &md5Padding, &md5PrintHash},
	{"sha224", "SHA224", 64,  &sha224InitHash, &sha256EncodeBloc, &sha256Padding, &sha224PrintHash},
	{"sha256", "SHA256", 64,  &sha256InitHash, &sha256EncodeBloc, &sha256Padding, &sha256PrintHash},
	{"sha384", "SHA384", 128, &sha384InitHash, &sha512EncodeBloc, &sha512Padding, &sha384PrintHash},
	{"sha512", "SHA512", 128, &sha512InitHash, &sha512EncodeBloc, &sha512Padding, &sha512PrintHash}
};

t_router_des routesDES[] = {
	{"des", &encodeCBC, &decodeCBC, 1},
	{"des-cbc", &encodeCBC, &decodeCBC, 1},
	{"des-cfb", &encodeCFB, &decodeCFB, 0},
	{"des-ctr", &encodeCTR, &decodeCTR, 0},
	{"des-ecb", &encode_decodeECB, &encode_decodeECB, 1},
	{"des-ofb", &encodeOFB, &encodeOFB, 0}
};

int	getRouter(char **argv, char *name) {
	for (int index = 0; index < 5; index++) {
		if (!ft_strcmp(routesHash[index].name, name)) {
			routerHash(argv + 2, &routesHash[index]);
			return (1);
		}
	}
	for (int index = 0; index < 6; index++) {
		if (!ft_strcmp(routesDES[index].name, name)) {
			routerDES(argv + 2, &routesDES[index]);
			return (1);
		}
	}
	if (!ft_strcmp(name, "base64")) {
		routerBase64(argv + 2);
		return (1);
	}
	return (0);
}