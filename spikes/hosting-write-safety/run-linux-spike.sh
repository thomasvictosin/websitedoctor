#!/bin/sh
set -eu

spike_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

docker run --rm \
  --volume "$spike_dir:/src:ro" \
  --workdir /src \
  gcc:14-bookworm \
  sh -eu -c 'gcc -std=c11 -O2 -Wall -Wextra -Werror hosting-write-spike.c -o /tmp/hosting-write-spike && /tmp/hosting-write-spike'
