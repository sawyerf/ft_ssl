#include "ft_ssl.h"
#include "libft.h"
#include <sys/stat.h>
#include <fcntl.h> 

int sha224Router(char **argv) {
	char	*message = NULL;
	t_optpars opt;
	t_hash	hash;

	options(argv, &message, &opt);
	sha224InitHash(&hash);
	if (message) {
		sha256GetArg(message, &hash);
	} else {
		int fd = 0;
		if (opt.arg && opt.arg[0]) {
			if ((fd = open(opt.arg[0], O_RDONLY)) < 0) {
				ft_dprintf(2, "ERROR: Can't open file `%s'\n", opt.arg[0]);
				exit(1);
			}
		}
		ft_printf("%d\n", fd);
		sha256GetFd(fd, &hash);
	}
	if (!ft_tabfind(opt.opt, "-q")) {
		sha256PrintHash(&hash);
	}
	return 0;
}