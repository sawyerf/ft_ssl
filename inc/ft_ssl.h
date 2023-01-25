#ifndef FT_SSL_H
# define FT_SSL_H

# include "libft.h"

#define DES_SIZE_READ 3 * 4
#define HASH32_SIZE 8 * 4

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

typedef struct		s_des
{
	int				fdInput;
	int				fdOutput;
	unsigned long	key;
	unsigned long	iv;
	int				isDecode;
	int				isBase64;
	char			*keyArg;
	char			*ivArg;
	char			*passArg;
	char			*saltArg;
	unsigned long keys[16];
}					t_des;

typedef unsigned long (*t_encodeDES)(t_des *des, unsigned long data, unsigned long *keys);

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

typedef struct		s_router_des
{
	char			name[10];
	t_encodeDES		encode;
	t_encodeDES 	decode;
	int				isPadding;
}					t_router_des;

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
void	routerBase64(char **argv);
void	base64Encode(unsigned char *message, size_t size, int fd);
size_t	base64Decode(unsigned char *message, size_t size, char *output);

// DES
void	generateKey(unsigned long key, unsigned long *keys);
unsigned long desEncrypt(unsigned long bloc, unsigned long *keys);
size_t	desPadding(void *d, size_t size);
void	routerDES(char **argv, t_router_des *route);

unsigned long encode_decode3ECB(t_des *des, unsigned long data, unsigned long *keys);
// DES-ECB
unsigned long encode_decodeECB(t_des *des, unsigned long data, unsigned long *keys);

// DES-CBC
unsigned long decodeCBC(t_des *des, unsigned long data, unsigned long *keys);
unsigned long encodeCBC(t_des *des, unsigned long data, unsigned long *keys);

// DES-CFB
unsigned long decodeCFB(t_des *des, unsigned long data, unsigned long *keys);
unsigned long encodeCFB(t_des *des, unsigned long data, unsigned long *keys);

// DES-OFB
unsigned long decodeOFB(t_des *des, unsigned long data, unsigned long *keys);
unsigned long encodeOFB(t_des *des, unsigned long data, unsigned long *keys);

// DES-CTR
unsigned long decodeCTR(t_des *des, unsigned long data, unsigned long *keys);
unsigned long encodeCTR(t_des *des, unsigned long data, unsigned long *keys);

// router
int		getRouter(char **argv, char *name);
void	routerHash(char **argv, t_router *router);
void	getArg(char *message, size_t len, t_hash *hash, t_router *route);

// HMAC
void	hmacSha256(t_hash *hash, char *key, size_t lenKey, char *message, size_t lenMes);

// PBKDF2
void	pbkdf2(char *password, unsigned long salt, t_hash *hash, unsigned int iter);

// Print
void	print_bits(void *str, size_t len);
void	print_dbits(char *name, void *str, size_t len);


void	options(char **argv, char **message, t_optpars *ret);
unsigned int swap32(unsigned int num);
size_t	swap64(size_t val);
unsigned int	leftRotate(unsigned int n, unsigned int d);
unsigned int	rightRotate(unsigned int n, unsigned int d);
unsigned int	rightShift(unsigned int n, unsigned int d);
unsigned long	rightRotate64(unsigned long n, unsigned long d);
ssize_t	turboRead(int fd, void *data, size_t sizeBloc, int isDelWhite);
void	turboNShift(void *n, int size);
unsigned long	atoi_hex(char *str);
int		isHex(char *str);

#endif