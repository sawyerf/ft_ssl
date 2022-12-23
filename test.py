import re
import os
from colorama import Fore, Style

def runCommands(algo, stdin, name):
	myStdout = os.popen(f'echo -n "{stdin}" | ./ft_ssl {algo}').read()
	hisStdout = os.popen(f'echo -n "{stdin}" | openssl {algo}').read()

	myHash = re.findall(r'([a-f0-9]{10,})', myStdout)[0]
	hisHash = re.findall(r'([a-f0-9]{10,})', hisStdout)[0]
	if (myHash == hisHash and myHash != '' and myHash != None):
		print(Fore.GREEN, end='')
		print(f'{algo}("{name}"): OK\'')
		# pass
	else:
		print(Fore.RED, end='')
		print('============= FAIL ===============')
		print(algo)
		print(stdin)
		print('ft_ssl: ', myHash)
		print('openssl:', hisHash)
		print('============= FAIL ===============')
	print(Style.RESET_ALL, end='')

def testAlgos(stdin, name):
	for algo in ['md5', 'sha224', 'sha256', 'sha384', 'sha512']:
		runCommands(algo, stdin, name)

for index in range(150):
	testAlgos('A' * index, f"'A' * {index}")

testAlgos('A' * 100000 , f"'A' * 10000")