#!/bin/bash

#You can also start a program as a background job with an "&" on the command line.
myprogram &

#Note that output (both stdout and stderr) will still go to the current tty, 
# so it's generally a good idea to redirect to /dev/null or to a log file, like so:
myprogram > ~/program.log 2>&1 &

#Linking a one file to another
ln -s <directoyr>/<file-to-be-linked> <directory>/<file-name>
        ^--- these directory is necessary ----^

#One liner for loops
for i in {1..5}; do echo "\\e[${i}m"; done

for((i=1;i<=10;i+=2)); do echo "Welcome $i times"; done

#Check if a file exists or not
if [ -f "/etc/passwd" ]; then echo "The file exists"; fi

if [ ! -f "/etc/bebebe" ]; then echo "The file does not exist"; fi
