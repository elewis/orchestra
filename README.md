
$ run /opt/splunk/bin/splunk stop
test1			success
test2			success
test3			error

$ tags list
splunk
splunk/master
splunk/indexer

$ tags set splunk
splunk

$ tags add splunk/master
splunk
splunk/master

$ tags remove splunk/master
splunk

$ hosts list
test1			splunk
test2			splunk
test3			splunk

$ exit
Goodbye
