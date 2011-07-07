#!/bin/sh
# Run this script from the waf source directory to build a custom waf script
# which includes autowaf (and the other listed tools)

if [ $# != 1 ]; then
    echo "Error: Path to autowaf.py must be passed as only argument"
    exit 1
fi

autowaf_py=$1

./waf-light -v --make-waf --tools=doxygen,swig,$autowaf_py --prelude=''
