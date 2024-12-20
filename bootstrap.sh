#!/bin/sh
rm -f config.cache aclocal.m4
autoreconf -i
automake --add-missing --copy >/dev/null 2>&1
