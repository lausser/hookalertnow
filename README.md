# hookalertnow
Gateway to ServiceNow for Prometheus Alertmanager and Nagios/Naemon/Icinga

## Alertmanager
Consists of a webserver *hookalertnow* which receives requests from an Alertmanager (passed through by the OMD site's Apache). The webserver calls the notificationforwarder with hookalernow formatter and forwarder.

## Nagios
Consists of a naenonow formatter, which passes the payload to the hookalertnow forwarder.
