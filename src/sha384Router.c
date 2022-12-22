#include "ft_ssl.h"
#include "libft.h"
#include <sys/stat.h>
#include <fcntl.h> 

// ca fonctionne pas avec 'a' * 64
int sha384Router(char **argv) {
	char	*message = NULL;
	t_optpars opt;
	t_hash64	hash;

	options(argv, &message, &opt);
	sha384InitHash(&hash);
	if (message) {
		sha512GetArg(message, &hash);
	} else {
		int fd = 0;
		if (opt.arg && opt.arg[0]) {
			if ((fd = open(opt.arg[0], O_RDONLY)) < 0) {
				ft_dprintf(2, "ERROR: Can't open file `%s'\n", opt.arg[0]);
				exit(1);
			}
		}
		sha512GetFd(fd, &hash);
	}
	if (!ft_tabfind(opt.opt, "-q")) {
		sha384PrintHash(&hash);
	}
	return 0;
}