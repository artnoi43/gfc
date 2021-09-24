#!/bin/sh

[  -f gfc ]\
&& cp -a gfc rgfc.sh ~/bin/.\
|| go build\
&& cp -a gfc rgfc.sh ~/bin/.;
