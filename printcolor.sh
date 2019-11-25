#!/bin/bash
#Reference Website: https://misc.flogisoft.com/bash/tip_colors_and_formatting


#FOREGROUND COLOR---------------------
BLACK=$'\e[30m'
RED=$'\e[31m'
GREEN=$'\e[32m' #seems to make a dark yellow
YELLOW=$'\e[33m'
BLUE=$'\e[34m'
MAGENTA=$'\e[35m'
CYAN=$'\e[36m'

LIGHT_GRAY=$'\e[37m'
LIGHT_RED=$'\e[91m'
LIGHT_GREEN=$'\e[92m'
LIGHT_YELLOW=$'\e[93m'
LIGHT_BLUE=$'\e[94m'
LIGHT_MAGENTA=$'\e[95m'
LIGHT_CYAN=$'\e[96m'
WHITE=$'\e[97m'

DARK_GRAY=$'\e[90m'

#FORMAT-------------------------------
BOLD=$'\e[1m'
DIM=$'\e[2m'
UNDERLINED=$'\e[4m'
BLINK=$'\e[5m'
INVERTED=$'\e[7m'
HIDDEN=$'\e[8m'

#BACKGROUND COLOR---------------------
B_BLACK=$'\e[40m'
B_RED=$'\e[41m'
B_GREEN=$'\e[42m'
B_YELLOW=$'\e[43m'
B_BLUE=$'\e[44m'
B_MAGENTA=$'\e[45m'
B_CYAN=$'\e[46m'
B_WHITE=$'\e[107m'

B_LIGHT_GRAY=$'\e[47m'
B_LIGHT_RED=$'\e[101m'
B_LIGHT_GREEN=$'\e[102m'
B_LIGHT_YELLOW=$'\e[103m'
B_LIGHT_BLUE=$'\e[104m'
B_LIGHT_MAGENTA=$'\e[105m'
B_LIGHT_CYAN=$'\e[106m'

B_DARK_GRAY=$'\e[100m'

#RESET--------------------------------
RESET=$'\e[0m' # No Format



GREEN=$'\e[32m'
YELLOW=$'\e[33m'
echo "${LIGHT_GREEN}Test"
echo "${BOLD}${RED}Bold test"
echo "${RESET}Color should be removed"
