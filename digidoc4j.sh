#!/bin/bash

CLASSPATH=$CLASSPATH:out/production/digidoc4j:build
for i in lib/*.jar; do
	CLASSPATH="$CLASSPATH:$i"
done

java -Xmx512m -classpath $CLASSPATH org.digidoc4j.main.DigiDoc4J "$@"
