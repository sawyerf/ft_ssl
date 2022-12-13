#ifndef FT_SSL_H
# define FT_SSL_H

#include <stddef.h>
#include "libft.h"

long *ft_md5(unsigned char *message, size_t len);

typedef struct	s_512bloc
{
	unsigned int	a;
	unsigned int	b;
	unsigned int	c;
	unsigned int	d;
}				t_512bloc;

#endif