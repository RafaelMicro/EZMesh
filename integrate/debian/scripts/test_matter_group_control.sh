#!/bin/bash

BEGIN=$1
END=$2
GROUP_NAME=$3
GROUP_PART=$4
FLAG=$5


for ((i=$BEGIN; i<=$END; i++))
do
    matter-tool group_join $GROUP_NAME L$i $FLAG
    matter-tool group_join $GROUP_PART L$i $FLAG

done