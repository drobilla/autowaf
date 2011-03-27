#!/bin/sh
# Run this script from the waf source directory to build a custom waf script
# which includes autowaf (and the other listed tools)

./waf-light -v --make-waf --tools=doxygen,swig,/path/to/autowaf/autowaf.py --prelude=''
