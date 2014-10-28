#!/bin/sh
set -x

: ${BISERVER_HOME:?"Please set BISERVER_HOME"}
echo ${HOME} | grep -q ${USER}

if [ $? -ne 0 ]; then 
   echo "home directory is not same as user, hint use sudo -i"
   exit -1
fi

DIR_REL=`dirname $0`
cd $DIR_REL
DIR=`pwd`
cd -
mvn install
java -jar Saxon-HE-9.4.jar -s:src/erpi-aggregates.xml -xsl:style.xsl -o:target/erpi-schema.xml
mvn process-resources

