call mvn install
java -jar %HOME%\.m2\repository\net\sf\saxon\Saxon-HE\9.4\saxon-he-9.4.jar -s:src\erpi-aggregates-xtuple.xml -xsl:style.xsl -o:target\erpi-schema.xml
call mvn process-resources
