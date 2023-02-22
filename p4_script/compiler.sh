#!/bin/bash
rm -r ./build
mkdir ./build
p4c-bm2-ss --p4v 16 --p4runtime-files ./build/switch.p4info.txt -o ./build/switch.json ./switch.p4