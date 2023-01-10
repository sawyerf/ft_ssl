import re
import os
from colorama import Fore, Style

def runCommands(stdin, key, name):
	open('.test', 'w').write(stdin)
	myStdout = os.popen(f'cat .test | ./ft_ssl des-ecb -k {key} | ./ft_ssl des-ecb -d -k {key}').read()

	if (myStdout == stdin):
		# print(Fore.GREEN, end='')
		# print(f'{algo}("{name}"): OK\'')
		pass
	else:
		print(Fore.RED, end='')
		print('============= FAIL ===============')
		print(name)
		print(stdin)
		print(myStdout)
		print('============= FAIL ===============')
	print(Style.RESET_ALL, end='')


for index in range(150):
	runCommands('A' * index, '0123456789ABCDEF', f"'A' * {index}")

runCommands('A' * 100000 , '0123456789ABCDEF', f"'A' * 10000")