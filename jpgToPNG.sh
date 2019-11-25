#/bin/bash

for i in $(ls | grep jpg);
  do
   mv $i $i.png;
  done
