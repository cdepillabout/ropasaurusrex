#!/usr/bin/env bash

while true ; do
    ./breaker.hs > output
    inotifywait ./breaker.hs -e modify
done
