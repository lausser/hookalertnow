import time
import os
import json
import time
from datetime import datetime
from notificationforwarder.baseclass import NotificationFormatter, FormattedEvent
import logging


class NaenonowFormatter(NotificationFormatter):
    def format_event(self, event):
        logger = logging.getLogger("naenonow")
        host_name = event.eventopts.get("HOSTNAME")
        service_description = event.eventopts.get("SERVICEDESC", None)
        if service_description:
            event.event_topic = f"{host_name}__{service_description}"
            event.severity = event.eventopts.get("SERVICESTATE").lower()
            description = event.eventopts.get("SERVICEOUTPUT")
            if event.eventopts.get("LONGSERVICEOUTPUT"):
                description += "\n"+event.eventopts.get("LONGSERVICEOUTPUT")
            short_description = f"{host_name} / {service_description} is {event.severity}"
        else:
            event.event_topic = f"{host_name}"
            event.severity = event.eventopts.get("HOSTSTATE").lower()
            description = event.eventopts.get("HOSTOUTPUT")
            if event.eventopts.get("LONGHOSTOUTPUT"):
                description += "\n"+event.eventopts.get("LONGHOSTOUTPUT")
            short_description = f"{host_name} is {event.severity}"
            event.severity = "ok" if event.severity == "up" else "critical"

        event.status = "resolved" if event.eventopts.get("NOTIFICATIONTYPE") == "RECOVERY" else "firing"
        event.payload = {
            "description": description,
            "short_description": short_description,
            "cmdb_ci": host_name,
            "business_service": "Linux",
            "assignment_group": event.eventopts.get("SERVICEASSIGNMENTGROUP", event.eventopts.get("ASSIGNMENTGROUP", os.environ.get("SERVICENOW_DEFAULT_ASSIGNMENT_GROUP", "-assignment-group-unknown-"))),
        }
        event.summary = f"naemon sent {event.payload}"
        logger.info(f"Formatted {event.event_topic} {event.severity} {event.status}")

