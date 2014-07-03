javac -cp ..\buildlib\commons-logging-1.0.4.jar;..\buildlib\mondrian.jar com\erpi\mdxudf\GetDateInfo.java
jar -cf ..\lib\mdxudf.jar com\erpi\mdxudf\GetDateInfo.class