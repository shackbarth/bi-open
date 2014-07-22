#!/bin/sh
LOG_FILE='start_bi.log'
log() {
	echo $@
	echo $@ >> $LOG_FILE
}
cdir() {
	cd $1
	log "Changing directory to $1"
}
log ""
log "##########################################################"
log "##########################################################"
log "Start BI server listening on port 8080 and on 8444 for SSL"
log "##########################################################"
log "##########################################################"
log ""
cdir ../../ErpBI/biserver-ce/tomcat/bin/
export CATALINA_OPTS="-Djava.awt.headless=true -Xms256m -Xmx768m -XX:MaxPermSize=256m -Dsun.rmi.dgc.client.gcInterval=3600000 -Dsun.rmi.dgc.server.gcInterval=3600000"
JAVA_HOME=$_PENTAHO_JAVA_HOME
sh startup.sh

log ""
log "####################################################################"
log "####################################################################"
log "Refresh repository and clear OLAP Cache. Standby, this take a minute"
log "####################################################################"
log "####################################################################"
log ""

sleep 20

wget -O tempresponse.txt "http://localhost:8080/pentaho/Publish?publish=now&class=org.pentaho.platform.engine.services.solution.SolutionPublisher&userid=admin&password=Car54WhereRU"
rm tempresponse.txt
wget -O tempresponse.txt "http://localhost:8080/pentaho/ViewAction?solution=admin&path=&action=clear_mondrian_schema_cache.xaction&userid=admin&password=Car54WhereRU"
rm tempresponse.txt