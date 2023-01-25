#!/bin/bash

echo -n | ./ft_ssl des -p $1 -s $2 1>&-
echo =====================
echo -n | openssl des -pass "pass:$1" -S "$2" -provider legacy -provider default -iter $3 -P