import re
import os
from colorama import Fore, Style
import subprocess

def runCommands(stdin, name):
	open('.test', 'wb').write(stdin)

	try:
		myStdout = subprocess.check_output(f'cat .test | ./ft_ssl base64 | ./ft_ssl base64 -d', shell=True)
	except Exception as e:
		print(Fore.RED, end='')
		print('============= FAIL ===============')
		print(name)
		print(stdin)
		print(e)
		print('============= FAIL ===============')
		return

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
	print(Style.RESET_ALL, end='')

for index in range(150):
	runCommands(b'A' * index, f"'A' * {index}")

for index in range(150):
	runCommands(open('/dev/random', 'rb').read(index), f"'rand' * {index}")

