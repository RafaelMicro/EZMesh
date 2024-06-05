#!/bin/bash

BEGIN=$1
END=$2

for ((i=$BEGIN; i<=$END; i++))
do
    matter-tool connect L$i LIGHT 20202021 3840 $3
    matter-tool onoff off L$i $3
done