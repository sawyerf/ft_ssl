#include "ft_ssl.h"
#include "libft.h"
#include <fcntl.h> 

void router(char **argv, char *algo, t_getFd getFd, t_getArg getArg, t_printHash printHash) {
	char	*message = NULL;
	t_optpars opt;
	t_hash	hash;
	int fd;

	options(argv, &message, &opt);
	// STDIN
	if (ft_tabfind(opt.opt, "-p")) {
		if (!ft_tabfind(opt.opt, "-q")) ft_printf("%s(\"", algo);
		getFd(0, &hash, 1);
		if (!ft_tabfind(opt.opt, "-q")) ft_printf("\")= ");
		if (ft_tabfind(opt.opt, "-q")) ft_printf("\n");
		printHash(&hash);
		ft_printf("\n");
	} else if ((!message && (!opt.arg))) {
		getFd(0, &hash, 0);
		if (!ft_tabfind(opt.opt, "-q") && !ft_tabfind(opt.opt, "-r")) ft_printf("%s(stdin)= ", algo);
		printHash(&hash);
		if (!ft_tabfind(opt.opt, "-q") && ft_tabfind(opt.opt, "-r")) ft_printf(" stdin");
		ft_printf("\n");
	}
	// -s message
	if (message) {
		getArg(message, &hash);
		if (!ft_tabfind(opt.opt, "-q") && !ft_tabfind(opt.opt, "-r")) ft_printf("%s(\"%s\")= ", algo, message);
		printHash(&hash);
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
			getFd(fd, &hash, 0);
			if (!ft_tabfind(opt.opt, "-q") && !ft_tabfind(opt.opt, "-r")) ft_printf("%s(%s)= ", algo, opt.arg[index]);
			printHash(&hash);
			if (!ft_tabfind(opt.opt, "-q") && ft_tabfind(opt.opt, "-r")) ft_printf(" *%s", opt.arg[index]);
			ft_printf("\n");
			close(fd);
		}
	}
}

void router64(char **argv, char *algo, t_getFd64 getFd, t_getArg64 getArg, t_printHash64 printHash) {
	char	*message = NULL;
	t_optpars opt;
	t_hash64	hash;
	int fd;

	options(argv, &message, &opt);
	// STDIN
	if (ft_tabfind(opt.opt, "-p")) {
		if (!ft_tabfind(opt.opt, "-q")) ft_printf("%s(\"", algo);
		getFd(0, &hash, 1);
		if (!ft_tabfind(opt.opt, "-q")) ft_printf("\")= ");
		if (ft_tabfind(opt.opt, "-q")) ft_printf("\n");
		printHash(&hash);
		ft_printf("\n");
	} else if ((!message && (!opt.arg))) {
		getFd(0, &hash, 0);
		if (!ft_tabfind(opt.opt, "-q") && !ft_tabfind(opt.opt, "-r")) ft_printf("%s(stdin)= ", algo);
		printHash(&hash);
		if (!ft_tabfind(opt.opt, "-q") && ft_tabfind(opt.opt, "-r")) ft_printf(" stdin");
		ft_printf("\n");
	}
	// -s message
	if (message) {
		getArg(message, &hash);
		if (!ft_tabfind(opt.opt, "-q") && !ft_tabfind(opt.opt, "-r")) ft_printf("%s(\"%s\")= ", algo,  message);
		printHash(&hash);
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
			getFd(fd, &hash, 0);
			if (!ft_tabfind(opt.opt, "-q") && !ft_tabfind(opt.opt, "-r")) ft_printf("%s(%s)= ", algo, opt.arg[index]);
			printHash(&hash);
			if (!ft_tabfind(opt.opt, "-q") && ft_tabfind(opt.opt, "-r")) ft_printf("%s", message);
			ft_printf("\n");
			close(fd);
		}
	}
}