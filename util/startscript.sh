#!/bin/bash

util_dir=$(readlink -f $(dirname $0))

function crs-transform() {
    (workon crs-test && \
    eval "python $util_dir/transform-testcase/transform.py $@")
}