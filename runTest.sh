#!/bin/bash
make clean &>/dev/null
make &> /dev/null

cp test/*.csv . >/dev/null
cp test/certificates/*.crt . >/dev/null

./certcheck sample_input.csv 

echo "-- START DIFF --"
diff output.csv sample_output.csv
echo "-- END DIFF --"

rm *.csv > /dev/null
rm *.crt > /dev/null

make clean &>/dev/null