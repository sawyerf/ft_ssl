#ifndef FT_SSL_H
# define FT_SSL_H

# include <stddef.h>
# include "libft.h"

typedef struct		s_hash
{
	unsigned int	H0;
	unsigned int	H1;
	unsigned int	H2;
	unsigned int	H3;
	unsigned int	H4;
	unsigned int	H5;
	unsigned int	H6;
	unsigned int	H7;
}					t_hash;

// md5
int md5Router(char **argv);
void initHash(t_hash *hash);
void md5Padding(unsigned char *message, size_t full_len, t_hash *hash);
void encode512bloc(t_hash *hash, unsigned int *message);

// sha256
int sha256Router(char **argv);
void shaInitHash(t_hash *hash);
void shaPadding(unsigned char *message, size_t full_len, t_hash *hash);
void shaEncode512Bloc(t_hash *hash, unsigned int *message);
void shaPrintHash(t_hash *hash);

// Print
char *printHash(t_hash *hash);
void print_bits(unsigned char *str, size_t len);

int options(char **argv, char **message, t_optpars *ret);
unsigned int swap32(unsigned int num);
size_t swap64(size_t val);

#endif