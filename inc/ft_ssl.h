#ifndef FT_SSL_H
# define FT_SSL_H

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

	unsigned long	HH0;
	unsigned long	HH1;
	unsigned long	HH2;
	unsigned long	HH3;
	unsigned long	HH4;
	unsigned long	HH5;
	unsigned long	HH6;
	unsigned long	HH7;
}					t_hash;

typedef void (*t_initHash)(t_hash *hash);
typedef void (*t_encodeBloc)(t_hash *hash, void *message);
typedef void (*t_padding)(unsigned char *message, size_t full_len, t_hash *hash);
typedef void (*t_printHash)(t_hash *hash);

typedef struct		s_router
{
	char			name[10];
	char			algo[10];
	size_t			sizeBloc;
	t_initHash		initHash;
	t_encodeBloc	encodeBloc;
	t_padding		padding;
	t_printHash		printHash;
}					t_router;

// md5
void md5InitHash(t_hash *hash);
void md5EncodeBloc(t_hash *hash, void *message);
void md5Padding(unsigned char *message, size_t full_len, t_hash *hash);
void md5PrintHash(t_hash *hash);

// sha224
void sha224InitHash(t_hash *hash);
void sha224PrintHash(t_hash *hash);

// sha256
void sha256InitHash(t_hash *hash);
void sha256EncodeBloc(t_hash *hash, void *message);
void sha256Padding(unsigned char *message, size_t full_len, t_hash *hash);
void sha256PrintHash(t_hash *hash);

// sha384
void sha384InitHash(t_hash *hash);
void sha384PrintHash(t_hash *hash);

// sha512
void sha512InitHash(t_hash *hash);
void sha512Padding(unsigned char *message, size_t full_len, t_hash *hash);
void sha512EncodeBloc(t_hash *hash, void *message);
void sha512PrintHash(t_hash *hash);

// Base64
void	base64Encode(unsigned char *message, size_t size);
void	base64Decode(unsigned char *message, size_t size);

// router
t_router	*getRouter(char *name);
void router(char **argv, t_router *router);

// Print
void print_bits(unsigned char *str, size_t len);

void options(char **argv, char **message, t_optpars *ret);
unsigned int swap32(unsigned int num);
size_t swap64(size_t val);
unsigned int leftRotate(unsigned int n, unsigned int d);
unsigned int rightRotate(unsigned int n, unsigned int d);
unsigned int rightShift(unsigned int n, unsigned int d);
unsigned long rightRotate64(unsigned long n, unsigned long d);

#endif