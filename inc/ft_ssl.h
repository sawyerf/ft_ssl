#ifndef FT_SSL_H
# define FT_SSL_H

# include <stddef.h>
# include "libft.h"

typedef struct		s_hash
{
	unsigned int	H1;
	unsigned int	H2;
	unsigned int	H3;
	unsigned int	H4;
}					t_hash;

void init_hash(t_hash *hash);
void padding(unsigned char *message, size_t full_len);
void encode512bloc(t_hash *hash, unsigned int *message);
void Array32ToLittleEndian(unsigned int *message, size_t size);
char *printHash(t_hash *hash);
long *ft_md5(unsigned char *message, size_t len);

#endif