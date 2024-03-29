NAME =		ft_ssl

CC =		gcc

INC_DIR =	inc

INC_FILE =	ft_ssl.h
		
SRC_DIR =	src

SRC_FILE =	main.c \
			utils.c \
			des.c \
			des-cbc.c \
			des-cfb.c \
			des-ctr.c \
			des-ecb.c \
			hmac-sha256.c \
			des-ofb.c \
			md5.c \
			sha224.c \
			sha384.c \
			sha256.c \
			sha512.c \
			base64.c \
			router-hash.c \
			router-des.c \
			router-get.c \
			pbkdf2.c \

CFLAGS =	-I $(INC_DIR) -I libft/inc/ -g -Wall -Werror -Wextra

OBJ_DIR =	.obj
OBJ_FILE =	$(SRC_FILE:.c=.o)

CRT_DIR =	./

SRC = 		$(addprefix $(SRC_DIR)/,$(SRC_FILE))
INC = 		$(addprefix $(INC_DIR)/,$(INC_FILE))
OBJ = 		$(addprefix $(OBJ_DIR)/,$(OBJ_FILE))
CRT = 		$(addprefix $(OBJ_DIR)/,$(CRT_DIR))

all: $(NAME)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(INC) Makefile
	@printf "\033[0;32m[$(NAME)] Compilation [o.]\033[0;0m\r"
	@mkdir -p $(CRT) 2> /dev/null || true
	@$(CC) $(CFLAGS) -c $< -o $@
	@printf "\033[0;32m[$(NAME)] Compilation [.o]\033[0;0m\r"

norm:
	@norminette $(SRC)
	@norminette $(INC)

$(NAME): $(OBJ)
	@printf "\033[0;32m[$(NAME)] Compilation [OK]\033[0;0m\n"
	@make -C libft/
	@$(CC) $(CFLAGS) $(DEBUG) $(OBJ) libft/libft.a -o $(NAME)

clean:
	@make clean -C libft/
	@/bin/rm -f $(OBJ)
	@/bin/rm -rf $(OBJ_DIR)
	@printf "\033[0;31m[$(NAME)] Deleted *.o\033[0;0m\n"

fclean: clean
	@/bin/rm -f $(NAME)
	@/bin/rm -f libft/libft.a
	@printf "\033[0;31D[$(NAME)] Deleted 42sh\033[0;0m\n"

re: fclean all

.PHONY: all clean fclean re