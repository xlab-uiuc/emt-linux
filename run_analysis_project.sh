#!/usr/bin/env bash

set -euo pipefail

make compile_commands.json

./parse_commands.pl > list.txt

parallel -q -j"$(nproc)" ./run_analysis_file.sh {} < list.txt | tee result.txt
