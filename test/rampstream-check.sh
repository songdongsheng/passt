#! /bin/sh

(rampstream check "$@" 2>&1; echo $? > rampstream.status) | tee rampstream.err
