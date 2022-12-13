#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ft_ssl.h"

void *ft_realloc(void *ptr, size_t size) {
	void *new = malloc(size);
	if (ptr) {
		ft_memcpy(new, ptr, size);
		free(ptr);
	}
	return new;
}

// Read from stdin until EOF and store input in first argument and return size of input
size_t getinput(char **input) {
	size_t len = 0;
	size_t size = 0;
	char buf[4096];

	while ((len = read(0, buf, 4096)) > 0) {
		// printf("len: %zu, size: %zu\n", len, size);
		*input = realloc(*input, size + len + 1024);
		ft_memcpy(*input + size, buf, len);
		size += len;
	}
	return size;
}

int main(int argc, char *argv[])
{
	char *input = NULL;
	size_t len = 0;

	len = getinput(&input);
	ft_md5(input, len);
	return 0;
}