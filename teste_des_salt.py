import re
import os
from colorama import Fore, Style
import subprocess

def runCommands(algo, stdin, password, iter, name):
    open('.test', 'w').write(stdin)

    try:
        myStdoutEncode = subprocess.check_output(f'./ft_ssl des-{algo} -i .test  -p "{password}" 2>&- | openssl des-{algo} -pass "pass:{password}" -d -provider legacy -provider default -pbkdf2 -iter 1000 2>&-', shell=True)
        
        # opensslStdoutEncode = subprocess.check_output(f'openssl des-{algo} -pass "pass:{password}" -in .test -provider legacy -provider default -pbkdf2 -iter 1000 | ./ft_ssl des-{algo} -d  -p "{password}" 2>&-', shell=True)
    except Exception as e:
        print(Fore.RED, end='')
        print('============= FAIL ===============')
        print(f'des-{algo}')
        print(name)
        print(stdin)
        print(e)
        print('============= FAIL ===============')
        return

    stdin = stdin.encode()
    if (myStdoutEncode == stdin):
    # if (myStdoutEncode == stdin and opensslStdoutEncode == stdin):
        print(Fore.GREEN, end='')
        print(f'openssl des-{algo} -pass "pass:{password}" -in .test -provider legacy -provider default -pbkdf2 -iter 1000 | ./ft_ssl des-{algo} -d  -p "{password}" 2>&-')

        print(f'{algo}("{name}"): OK\'')
        pass
    else:
        print(Fore.RED, end='')
        print('============= FAIL ===============')
        print(f'des-{algo}')
        print(name)
        # print(f'./ft_ssl des-{algo} -i .test  -p "{password}" 2>&- | openssl des-{algo} -pass "pass:{password}" -d -provider legacy -provider default -pbkdf2 -iter 1000 2>&-')
        print(f'openssl des-{algo} -pass "pass:{password}" -in .test -provider legacy -provider default -pbkdf2  | ./ft_ssl des-{algo} -d  -p "{password}" 2>&-')
        print(f"stdin =\t\t{stdin}")
        print(f"myStdout =\t{myStdoutEncode}")
        print(f"opensslStdoutEncode =\t{opensslStdoutEncode}")
    print(Style.RESET_ALL, end='')


algos = ['ecb', 'cbc', 'ofb', 'cfb']
for index in range(20):
    for iter in [1000]:
        for key in ['', 'lolipop', 'A'*50]:
            for algo in algos:
                runCommands(algo, 'A' * index, key, iter, f"'A' * {index}")

for algo in algos:
    runCommands(algo, 'A' * 100000 , '0123456789ABCDEF', 4096, f"'A' * 10000")
