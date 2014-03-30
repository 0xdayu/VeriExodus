#!/bin/bash
if [[ $0 != *bash ]];then
    echo "Please source this script to set PYTHONPATH."
else
    curr_folder=$(pwd 2>&1)
    if [[ $PYTHONPATH == *"$curr_folder"* ]]; then
        echo "$curr_folder already present in PYTHONPATH."
    else
        echo "Adding $curr_folder to PYTHONPATH."
        PYTHONPATH="$PYTHONPATH:$curr_folder"
        export PYTHONPATH
    fi
fi
cd c-bytearray
python setup.py build
cp build/lib.*/c_wildcard.so ../utils/.
rm -rf build
cd ..

