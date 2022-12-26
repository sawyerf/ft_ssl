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

typedef struct		s_hash64
{
	unsigned long	H0;
	unsigned long	H1;
	unsigned long	H2;
	unsigned long	H3;
	unsigned long	H4;
	unsigned long	H5;
	unsigned long	H6;
	unsigned long	H7;
}					t_hash64;

typedef void (*t_getFd)(int fd, t_hash *hash, int isPrint);
typedef void (*t_getArg)(char *message, t_hash *hash);
typedef void (*t_printHash)(t_hash *hash);

typedef void (*t_getFd64)(int fd, t_hash64 *hash, int isPrint);
typedef void (*t_getArg64)(char *message, t_hash64 *hash);
typedef void (*t_printHash64)(t_hash64 *hash);

// md5
int  md5Router(char **argv);
void md5InitHash(t_hash *hash);
void md5Padding(unsigned char *message, size_t full_len, t_hash *hash);
void md5EncodeBloc(t_hash *hash, unsigned int *message);
void md5PrintHash(t_hash *hash);

// sha224
int  sha224Router(char **argv);
void sha224InitHash(t_hash *hash);
void sha224PrintHash(t_hash *hash);

// sha256
int  sha256Router(char **argv);
void sha256InitHash(t_hash *hash);
void sha256Padding(unsigned char *message, size_t full_len, t_hash *hash);
void sha256EncodeBloc(t_hash *hash, unsigned int *message);
void sha256PrintHash(t_hash *hash);
void sha256GetFd(int fd, t_hash *hash, int isPrint);
void sha256GetArg(char *message, t_hash *hash);

// sha384
int  sha384Router(char **argv);
void sha384InitHash(t_hash64 *hash);
void sha384PrintHash(t_hash64 *hash);

// sha512
int  sha512Router(char **argv);
void sha512InitHash(t_hash64 *hash);
void sha512Padding(unsigned char *message, size_t full_len, t_hash64 *hash);
void sha512EncodeBloc(t_hash64 *hash, unsigned long *message);
void sha512PrintHash(t_hash64 *hash);
void sha512GetFd(int fd, t_hash64 *hash, int isPrint);
void sha512GetArg(char *message, t_hash64 *hash);

// router
int router(char **argv, char *algo, t_getFd getFd, t_getArg getArg, t_printHash printHash);
int router64(char **argv, char *algo, t_getFd64 getFd, t_getArg64 getArg, t_printHash64 printHash);

// Print
void print_bits(unsigned char *str, size_t len);

int options(char **argv, char **message, t_optpars *ret);
unsigned int swap32(unsigned int num);
size_t swap64(size_t val);
unsigned int leftRotate(unsigned int n, unsigned int d);
unsigned int rightRotate(unsigned int n, unsigned int d);
unsigned int rightShift(unsigned int n, unsigned int d);
unsigned long rightRotate64(unsigned long n, unsigned long d);

#endif