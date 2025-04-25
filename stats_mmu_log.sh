#!/bin/bash
echo 'R, W, I, nPMD, nPTE'

# log file
rg --count access=0 $1 
rg --count access=1 $1
rg --count access=2 $1
# grep -P 'PTE2=\w+' --only-matching $1 | sort | uniq | wc -l
# grep -P 'PTE3=\w+' --only-matching $1 | sort | uniq | wc -l

# awk is about 2-3 times faster than sort | uniq
# https://stackoverflow.com/a/56894789

rg -e 'PTE2=\w+' --only-matching $1 | awk '!seen[$0]++' | wc -l 
rg -e 'PTE3=\w+' --only-matching $1 | awk '!seen[$0]++' | wc -l

