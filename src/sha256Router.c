#include "ft_ssl.h"
#include "libft.h"
#include <sys/stat.h>
#include <fcntl.h> 

int sha256Router(char **argv) {
	char	*message = NULL;
	t_optpars opt;
	t_hash	hash;

	options(argv, &message, &opt);
}