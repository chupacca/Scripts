#!/bin/bash
# Rename all *.txt to *.text
for f in *.jpg; do
    mv -- "$f" "${f%.jpg}.png"
done
