#!/bin/bash

USER='pikatracer'
PROJECT='Python-Projects'

#Create a new repository on the command line
#echo "# Python-Projects" >> README.md
git init
git add README.md
git commit -m "first commit"
git remote add origin git@github.com:$USER/$PROJECT.git
git push -u origin master

#Push an existing repository from the command line
#git remote add origin git@github.com:$USER/Python-Projects.git
#git push -u origin master


