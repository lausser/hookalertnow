import time
import os
import json
import time
from datetime import datetime
from notificationforwarder.baseclass import NotificationFormatter, FormattedEvent
import logging


class HookalertnowFormatter(NotificationFormatter):
    def format_event(self, event):
        logger = logging.getLogger("hookalertnow")
        labels = dict((k, v) for k, v in event.eventopts.get("labels", {}).items())
        annotations = dict((k, v) for k, v in event.eventopts.get("annotations", {}).items())

        if not "namespace" in labels:
            labels["namespace"] = "default"
        if not "cluster_id" in labels:
            labels["cluster_id"] = event.eventopts.get("generatorURL", "http://unknown-cluster").split("/")[2]

        event.event_topic = "__".join(labels.get(k, "unknown") for k in ["alertname", "cluster_id", "namespace"])
        event.severity = labels.get("severity", "critical")
        event.status = event.eventopts.get("status", "firing")
        annotations.update({"webhook_input": f"status = {event.status}, severity = {event.severity}"})
        # show the hostname of the alertmanager-webhook
        annotations.update({"gateway": event.eventopts.get("omd_originating_host", "unknown")})

        summary = annotations.get("summary", "-no summary-")
        short_description = f"{summary} in {labels['namespace']}@{labels['cluster_id']}"

        event.payload = {
            "description": annotations.get("description", "-no description-"),
            "short_description": short_description,
            "cmdb_ci": labels.get("cmdb_ci", "-cmdb-unknown-"),
            "business_service": labels.get("business_service", os.environ.get("SERVICENOW_DEFAULT_BUSINESS_SERVICE", "OpenShift")),
            "assignment_group": labels.get("assignment_group", os.environ.get("SERVICENOW_DEFAULT_ASSIGNMENT_GROUP", "-assignment-group-unknown-")),
            "comments": f"Labels:\n" + " \n".join([f"{k} = {v}" for k, v in sorted(labels.items())]) + f"\nAnnotations:\n" + " \n".join([f"{k} = {v}" for k, v in sorted(annotations.items())])
        }
        event.summary = f"alertmanager sent {event.payload}"
        logger.info(f"Formatted {event.event_topic} {event.severity} {event.status}")

    def split_events(self, bigevent):
        logger = logging.getLogger("hookalertnow")
        alerts = bigevent.get("alerts", [])
        logger.info(f"split payload into {len(alerts)} single events")

        # Liste der Topics und Status erstellen
        topics = [self._get_topic(alert) for alert in alerts]
        filtered_alerts = []

        for i, alert in enumerate(alerts):
            topic = topics[i]
            status = alert.get("status", "firing")
            # Skip resolved, wenn ein späterer Alert im selben Topic firing ist
            if status == "resolved":
                if any(t == topic and a.get("status", "firing") == "firing" for j, (t, a) in enumerate(zip(topics, alerts)) if j > i):
                    logger.info(f"Skipping resolved alert for {topic} due to subsequent firing in same payload")
                    continue
            filtered_alerts.append(alert)

        if len(filtered_alerts) != len(alerts):
            logger.info(f"Filtered down to {len(filtered_alerts)} events after skipping resolved alerts")
        return filtered_alerts

    def _get_topic(self, alert):
        labels = alert.get("labels", {})
        if not "namespace" in labels:
            labels["namespace"] = "default"
        if not "cluster_id" in labels:
            labels["cluster_id"] = alert.get("generatorURL", "http://unknown-cluster").split("/")[2]
        return "__".join(labels.get(k, "unknown") for k in ["alertname", "cluster_id", "namespace"])



"""
        # impact Auswirkung
        # 1 > 50
        # 2 < 50
        # 3 ein einzelner Benutzer
        # urgency Dringlichkeit
        # 1 Totalausfall
        # 2 Teilausfall
        # 3 wenn mal Zeit ist
        # i u
        # 3 3 = 3 - Einschränkung
        # 3 2 = 2 - Teilausfall
        # 3 1 = 1 - Totalausfall
        # 2 3 = 3 - Einschränkung
        # 2 2 = 2 - Teilausfall
        # 2 1 = 1 - Totalausfall
        # 1 3 = 3 - Einschränkung
        # 1 2 = 2 - Teilausfall
        # 1 1 = 1 - Totalausfall

    Incoming from Alertmanager
    {
      "receiver": "hookalertnow",
      "status": "firing",
      "alerts": [
        {
          "status": "firing",
          "labels": {
            "alertname": "MinutlyTest", <---
            "job": "minutlytest",       <---
            "monitor": "demo"           <---
          },
          "annotations": {
            "description": "minutly alert test", <-desc
            "summary": "minutly alert test"  <-short desc
          },
          "startsAt": "2025-03-10T11:59:24.061Z",
          "endsAt": "0001-01-01T00:00:00Z",
          "generatorURL": "http://f418b56abf02/demo/prometheus/graph?g0.expr=vector%281%29+%3E+0&g0.tab=1",
          "fingerprint": "b1fe7a5d2c9e5714"
        }
      ],
      "groupLabels": {
        "alertname": "MinutlyTest"
      },
      "commonLabels": {
        "alertname": "MinutlyTest",
        "job": "minutlytest",
        "monitor": "demo"
      },
      "commonAnnotations": {
        "description": "minutly alert test",
        "summary": "minutly alert test"
      },
      "externalURL": "http://f418b56abf02/demo/alertmanager",  <---- additional_info
      "version": "4",
      "groupKey": "{}/{}:{alertname=\"MinutlyTest\"}",
      "truncatedAlerts": 0
    }

"""
