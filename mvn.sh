#!/bin/bash

# $ test -f FILENAME
#   – or –
#  [ -f FILENAME ]

RED=$'\e[31m'
LIGHT_GREEN=$'\e[92m'

if [ -f "pom.xml" ]
then 
  echo "${LIGHT_GREEN}pom.xml is found...compile and rebuild the project${RESET}"
  mvn clean -f pom.xml
  mvn verify -f pom.xml
else
  echo "${RED}pom.xml is NOT found${RESET}"
fi



