import re
import os
from colorama import Fore, Style
import subprocess

def runCommands(algo, stdin, key, name):
	open('.test', 'w').write(stdin)

	stdin = stdin.encode()
	myEncode = stdin
	hisEncode = stdin
	
	try:
		# myStdout = os.popen(f'cat .test | ./ft_ssl des-ecb -k {key} | ./ft_ssl des-ecb -d -k {key}').read()
		# myStdoutB64 = os.popen(f'cat .test | ./ft_ssl des-ecb -a -k {key} | ./ft_ssl des-ecb -a -d -k {key}').read()
		myStdout = subprocess.check_output(f'cat .test | ./ft_ssl des-{algo} -k {key} -v {key} 2>&- | ./ft_ssl des-{algo} -d -k {key} -v {key}  2>&-', shell=True)
		myStdoutB64 = subprocess.check_output(f'cat .test | ./ft_ssl des-{algo} -a -k {key} -v {key} 2>&- | ./ft_ssl des-{algo} -a -d -k {key} -v {key} 2>&-', shell=True)
		myStdoutEncode = subprocess.check_output(f'cat .test | ./ft_ssl des-{algo} -k {key} -v {key} 2>&-', shell=True)
		if (algo != 'ctr'):
			hisStdoutEncode = subprocess.check_output(f'cat .test | openssl des-{algo} -provider legacy -provider default -iv {key} -K {key} 2>&-', shell=True)

			myEncode = subprocess.check_output(f'./ft_ssl des-{algo} -i .test -k {key} -v {key} 2>&- | openssl des-{algo} -K {key} -iv {key} -d -provider legacy -provider default 2>&-', shell=True)
			hisEncode = subprocess.check_output(f'openssl des-{algo} -K {key} -iv {key} -in .test -provider legacy -provider default 2>&- | ./ft_ssl des-{algo} -d -k {key} -v {key} 2>&-', shell=True)
			myEncode = subprocess.check_output(f'./ft_ssl des-{algo} -i .test -k {key} -v {key} -a 2>&- | openssl des-{algo} -K {key} -iv {key} -d -a -provider legacy -provider default 2>&-', shell=True)
			hisEncode = subprocess.check_output(f'openssl des-{algo} -K {key} -iv {key} -in .test -a -provider legacy -provider default 2>&- | ./ft_ssl des-{algo} -d -k {key} -v {key} -a  2>&-', shell=True)
		else:
			hisStdoutEncode = myStdoutEncode
	except Exception as e:
		print(Fore.RED, end='')
		print('============= FAIL ===============')
		print(f'des-{algo}')
		print(name)
		print(stdin)
		print(e)
		print('============= FAIL ===============')
		return

	if (myStdout == stdin and myStdoutB64 == stdin and myStdoutEncode == hisStdoutEncode and myEncode == stdin and hisEncode == stdin):
		print(Fore.GREEN, end='')
		print(f'{algo}("{name}"): OK\'')
		pass
	else:
		print(Fore.RED, end='')
		print('============= FAIL ===============')
		print(f'des-{algo}')
		print(name)
		print(stdin)
		print(myStdout)
		print(myStdoutB64)
		print(myStdoutEncode)
		print(hisStdoutEncode)
		# print('============= FAIL ===============')
	print(Style.RESET_ALL, end='')

algos = ['ecb', 'cbc', 'ofb', 'cfb', 'ctr']
for index in range(324):
	for key in ['0123456789ABCDEF', '012' '0', '122AAABBBBCCCEDEDFEFE5546546']:
		for algo in algos:
			runCommands(algo, 'A' * index, key, f"'A' * {index}")

for algo in algos:
	runCommands(algo, 'A' * 100000 , '0123456789ABCDEF', f"'A' * 10000")