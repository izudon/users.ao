#!/bin/bash

###
### Needs yq Ver.4 
###

f=src/main/resources/credentials-$1.yml
u=$(yq e '.spring.datasource.url' $f)
n=$(yq e '.spring.datasource.username' $f)
p=$(yq e '.spring.datasource.password' $f)

[[ "$u" =~ jdbc:mariadb://([^:/]+):([0-9]+)/([^?]+) ]] || exit 1
h=${BASH_REMATCH[1]}
P=${BASH_REMATCH[2]}
d=${BASH_REMATCH[3]}

mysql -h "$h" -P "$P" -u "$n" -p"$p" "$d"
