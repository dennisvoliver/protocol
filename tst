#!/bin/sh
./mc mc.hypixel.net `echo $1 | sed 's/:/ /'` >dump
#./mc localhost `echo $1 | sed 's/:/ /'` >dump 2>dump
#echo $?
exit $?
