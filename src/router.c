#include "ft_ssl.h"
#include "libft.h"
#include <fcntl.h> 

t_router routes[] = {
	{"md5",    "MD5",    64,  &md5InitHash, &md5EncodeBloc, &md5Padding, &md5PrintHash},
	{"sha224", "SHA224", 64,  &sha224InitHash, &sha256EncodeBloc, &sha256Padding, &sha224PrintHash},
	{"sha256", "SHA256", 64,  &sha256InitHash, &sha256EncodeBloc, &sha256Padding, &sha256PrintHash},
	{"sha384", "SHA384", 128, &sha384InitHash, &sha512EncodeBloc, &sha512Padding, &sha384PrintHash},
	{"sha512", "SHA512", 128, &sha512InitHash, &sha512EncodeBloc, &sha512Padding, &sha512PrintHash}
};

void getFd(int fd, t_hash *hash, int isPrint, t_router *route) {
	ssize_t len;
	size_t size = 0;
	unsigned char input[128];
	unsigned char buffer[128];

	route->initHash(hash);
	ft_bzero(input, route->sizeBloc);
	while ((len = read(fd, buffer, route->sizeBloc)) > 0) {
		if (isPrint) write(1, buffer, len);
		if ((size % route->sizeBloc) + len >= route->sizeBloc) {
			ft_memcpy(input + (size % route->sizeBloc), buffer, route->sizeBloc - (size % route->sizeBloc));
			route->encodeBloc(hash, (unsigned int *)input);
			ft_bzero(input, route->sizeBloc);
			ft_memcpy(input, buffer + (route->sizeBloc - (size % route->sizeBloc)), len - (route->sizeBloc - (size % route->sizeBloc)));
		} else {
			ft_memcpy(input + (size % route->sizeBloc), buffer, len);
		}
		size += len;
	}
	if (len == -1) {
		ft_dprintf(2, "ERROR: Failed read file\n");
		exit(1);
	}
	route->padding(input, size, hash);
}

void getArg(char *message, t_hash *hash, t_router *route) {
	size_t	len = ft_strlen(message);
	size_t	index = 0;
	unsigned char	current[128];

	route->initHash(hash);
	while (len - index >= route->sizeBloc) {
		route->encodeBloc(hash, (unsigned int*)message);
		message += route->sizeBloc;
		index += route->sizeBloc;
	}
	ft_bzero(current, route->sizeBloc);
	ft_memcpy(current, message, len - index);
	route->padding(current, len, hash);
}

void router(char **argv, t_router *route) {
	char	*message = NULL;
	t_optpars opt;
	t_hash	hash;
	int fd;

	options(argv, &message, &opt);
	// STDIN
	if (ft_tabfind(opt.opt, "-p")) {
		if (!ft_tabfind(opt.opt, "-q")) ft_printf("%s(\"", route->algo);
		getFd(0, &hash, 1, route);
		if (!ft_tabfind(opt.opt, "-q")) ft_printf("\")= ");
		if (ft_tabfind(opt.opt, "-q")) ft_printf("\n");
		route->printHash(&hash);
		ft_printf("\n");
	} else if ((!message && (!opt.arg))) {
		getFd(0, &hash, 0, route);
		if (!ft_tabfind(opt.opt, "-q") && !ft_tabfind(opt.opt, "-r")) ft_printf("%s(stdin)= ", route->algo);
		route->printHash(&hash);
		if (!ft_tabfind(opt.opt, "-q") && ft_tabfind(opt.opt, "-r")) ft_printf(" stdin");
		ft_printf("\n");
	}
	// -s message
	if (message) {
		getArg(message, &hash, route);
		if (!ft_tabfind(opt.opt, "-q") && !ft_tabfind(opt.opt, "-r")) ft_printf("%s(\"%s\")= ", route->algo, message);
		route->printHash(&hash);
		if (!ft_tabfind(opt.opt, "-q") && ft_tabfind(opt.opt, "-r")) ft_printf(" \"%s\"", message);
		ft_printf("\n");
	}
	// FILE
	if (opt.arg) {
		for (int index = 0; opt.arg[index]; index++) {
			if ((fd = open(opt.arg[index], O_RDONLY)) < 0) {
				ft_dprintf(2, "ERROR: Can't open file `%s'\n", opt.arg[index]);
				continue;
			}
			getFd(fd, &hash, 0, route);
			if (!ft_tabfind(opt.opt, "-q") && !ft_tabfind(opt.opt, "-r")) ft_printf("%s(%s)= ", route->algo, opt.arg[index]);
			route->printHash(&hash);
			if (!ft_tabfind(opt.opt, "-q") && ft_tabfind(opt.opt, "-r")) ft_printf(" *%s", opt.arg[index]);
			ft_printf("\n");
			close(fd);
		}
	}
}

t_router	*getRouter(char *name) {
	for (int index; index < 5; index++) {
		if (!ft_strcmp(routes[index].name, name))
		return &routes[index];
	}
	return NULL;
}