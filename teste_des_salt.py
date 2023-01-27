import re
import os
from colorama import Fore, Style
import subprocess

def runCommands(algo, stdin, password, iter, name):
    open('.test', 'w').write(stdin)

    stdin = stdin.encode()
    myEncode = stdin
    myEncode64 = stdin
    hisEncode = stdin
    hisEncodeB64 = stdin
    try:
        myEncode = subprocess.check_output(f'./ft_ssl des-{algo} -i .test  -p "{password}" 2>&- | openssl des-{algo} -pass "pass:{password}" -d -provider legacy -provider default -pbkdf2 -iter 1000 2>&-', shell=True)
        myEncode64 = subprocess.check_output(f'./ft_ssl des-{algo} -a -i .test  -p "{password}" 2>&- | openssl des-{algo} -pass "pass:{password}" -d -provider legacy -provider default -pbkdf2 -iter 1000 -a 2>&-', shell=True)
        
        hisEncode = subprocess.check_output(f'openssl des-{algo} -pass "pass:{password}" -in .test -provider legacy -provider default -pbkdf2 -iter 1000 | ./ft_ssl des-{algo} -d  -p "{password}" 2>&-', shell=True)
        hisEncodeB64 = subprocess.check_output(f'openssl des-{algo} -a -pass "pass:{password}" -in .test -provider legacy -provider default -pbkdf2 -iter 1000 | ./ft_ssl des-{algo} -a -d  -p "{password}" 2>&-', shell=True)
    except Exception as e:
        print(Fore.RED, end='')
        print('============= FAIL ===============')
        print(f'des-{algo}')
        print(name)
        print(stdin)
        print(e)
        print('============= FAIL ===============')
        return

    if (myEncode == stdin and myEncode64 == stdin and hisEncode == stdin and hisEncodeB64 == stdin):
        print(Fore.GREEN, end='')
        print(f'{algo}("{name}", "{key}"): OK\'')
        pass
    else:
        print(Fore.RED, end='')
        print('============= FAIL ===============')
        print(f'des-{algo}')
        print(name)
        print(f"stdin                  =\t{stdin}")
        print(f"ft         =\t{myEncode}")
        print(f"ftB64      =\t{myEncode64}")
        print(f"openssl    =\t{hisEncode}")
        print(f"opensslB64 =\t{hisEncodeB64}")
    print(Style.RESET_ALL, end='')


algos = ['ecb', 'cbc', 'ofb', 'cfb']
for index in range(1):
    for key in ['', 'lolipop', 'A'*100]:
        for algo in algos:
            runCommands(algo, 'A' * index, key, iter, f"'A' * {index}")

for algo in algos:
    runCommands(algo, 'A' * 100000 , '0123456789ABCDEF', 4096, f"'A' * 10000")
