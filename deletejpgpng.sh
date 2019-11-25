#!/bin/bash

for i in $(find -name *.jpg)
do
  shred -u $i;
done

for i in $(find -name *.png)
do
  shred -u $i;
done
