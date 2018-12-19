#!/bin/sh

#utility for developers creating utility jar for testing

ant -f jenkins_build.xml sd-dss
ant make.utility

if [ -d util ]; then
    rm -rf util/*.jar
    rm -rf util/*.log
fi

unzip -o dist/digidoc4j-util*.zip -d util
