#!/bin/bash
# Rename all *.txt to *.text
mkdir bckup
for f in *.webp; do
    dwebp $f -o $f.png
    mv $f bckup
done
