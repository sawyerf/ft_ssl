import re
import os
from colorama import Fore, Style
import subprocess

def runCommands(stdin, key, name):
	open('.test', 'w').write(stdin)

	try:
		# myStdout = os.popen(f'cat .test | ./ft_ssl des-ecb -k {key} | ./ft_ssl des-ecb -d -k {key}').read()
		# myStdoutB64 = os.popen(f'cat .test | ./ft_ssl des-ecb -a -k {key} | ./ft_ssl des-ecb -a -d -k {key}').read()
		myStdout = subprocess.check_output(f'cat .test | ./ft_ssl des-ecb -k {key} | ./ft_ssl des-ecb -d -k {key}', shell=True)
		myStdoutB64 = subprocess.check_output(f'cat .test | ./ft_ssl des-ecb -a -k {key} | ./ft_ssl des-ecb -a -d -k {key}', shell=True)
	except Exception as e:
		print(Fore.RED, end='')
		print('============= FAIL ===============')
		print(name)
		print(stdin)
		print(e)
		print(myStdout)
		# print(type(myStdoutB64))
		print('============= FAIL ===============')

	stdin = stdin.encode()
	if (myStdout == stdin and myStdoutB64 == stdin):
		# print(Fore.GREEN, end='')
		# print(f'{algo}("{name}"): OK\'')
		pass
	else:
		print(Fore.RED, end='')
		print('============= FAIL ===============')
		print(name)
		print(stdin)
		print(myStdout)
		print(myStdoutB64)
		print('============= FAIL ===============')
	print(Style.RESET_ALL, end='')


for index in range(150):
	runCommands('A' * index, '0123456789ABCDEF', f"'A' * {index}")

runCommands('A' * 100000 , '0123456789ABCDEF', f"'A' * 10000")