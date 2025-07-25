import json
import sqlite3
from datetime import datetime
import requests
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
import logging
import os
import hashlib
import urllib.parse
from notificationforwarder.baseclass import NotificationForwarder, timeout

# ServiceNow Konstanten
INCIDENT_STATE_NEW = "1"
INCIDENT_STATE_IN_PROGRESS = "2"
INCIDENT_STATE_ON_HOLD = "3"
INCIDENT_STATE_RESOLVED = "6"
INCIDENT_STATE_CLOSED = "7"
INCIDENT_STATE_CANCELLED = "8"

INCIDENT_URGENCY_LOW = "3"
INCIDENT_URGENCY_MEDIUM = "2"
INCIDENT_URGENCY_HIGH = "1"
INCIDENT_IMPACT_LOW = "3"
INCIDENT_IMPACT_MEDIUM = "2"
INCIDENT_IMPACT_HIGH = "1"

INCIDENT_PRIORITY_CRITICAL = "1"
INCIDENT_PRIORITY_HIGH = "2"
INCIDENT_PRIORITY_MODERATE = "3"
INCIDENT_PRIORITY_LOW = "4"
INCIDENT_PRIORITY_PLANNING = "5"

class HookalertnowForwarder(NotificationForwarder):
    def __init__(self, opts):
        super(self.__class__, self).__init__(opts)
        self.url = getattr(self, "url", "http://localhost:12345")
        self.username = getattr(self, "username", None)
        self.password = getattr(self, "password", None)
        self.insecure = getattr(self, "insecure", "yes")
        self.logger_name = getattr(self, "logger_name", "notificationforwarder_"+self.__class__.__name__.replace("Forwarder", "").lower())
        self.priority_mapping = []
        self.severity_to_priority = {}
        self.load_mappings_from_sqlite()

    def load_mappings_from_sqlite(self):
        logger = logging.getLogger(self.logger_name)
        db_path = os.environ["OMD_ROOT"] + "/var/tmp/svcnow.db"
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            # Tabellen erstellen
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                event_topic TEXT PRIMARY KEY,
                sys_id TEXT NOT NULL,
                number TEXT NOT NULL UNIQUE,
                severity TEXT,
                status TEXT,
                payload_hash TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                archived INTEGER DEFAULT 0
            )
            ''')
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS priority_mapping (
                order INTEGER PRIMARY KEY,
                impact INTEGER NOT NULL,
                urgency INTEGER NOT NULL,
                priority INTEGER NOT NULL
            )
            ''')
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS severity_to_priority (
                severity TEXT PRIMARY KEY,
                priority INTEGER NOT NULL
            )
            ''')
            # Default-Mappings mit Konstanten
            default_priority_mapping = [
                (100, INCIDENT_IMPACT_HIGH, INCIDENT_URGENCY_HIGH, INCIDENT_PRIORITY_CRITICAL),    # > 50 Benutzer, Totalausfall → Critical
                (101, INCIDENT_IMPACT_HIGH, INCIDENT_URGENCY_MEDIUM, INCIDENT_PRIORITY_HIGH),     # > 50 Benutzer, Teilausfall → High
                (102, INCIDENT_IMPACT_HIGH, INCIDENT_URGENCY_LOW, INCIDENT_PRIORITY_MODERATE),    # > 50 Benutzer, Einschränkung → Moderate
                (103, INCIDENT_IMPACT_MEDIUM, INCIDENT_URGENCY_HIGH, INCIDENT_PRIORITY_HIGH),     # <= 50 Benutzer, Totalausfall → High
                (104, INCIDENT_IMPACT_MEDIUM, INCIDENT_URGENCY_MEDIUM, INCIDENT_PRIORITY_MODERATE),  # <= 50 Benutzer, Teilausfall → Moderate
                (105, INCIDENT_IMPACT_MEDIUM, INCIDENT_URGENCY_LOW, INCIDENT_PRIORITY_LOW),       # <= 50 Benutzer, Einschränkung → Low
                (106, INCIDENT_IMPACT_LOW, INCIDENT_URGENCY_HIGH, INCIDENT_PRIORITY_MODERATE),    # Benutzer, Totalausfall → Moderate
                (107, INCIDENT_IMPACT_LOW, INCIDENT_URGENCY_MEDIUM, INCIDENT_PRIORITY_LOW),       # Benutzer, Teilausfall → Low
                (108, INCIDENT_IMPACT_LOW, INCIDENT_URGENCY_LOW, INCIDENT_PRIORITY_PLANNING)      # Benutzer, Einschränkung → Planning
            ]
            default_severity_mapping = [
                ('critical', INCIDENT_PRIORITY_CRITICAL),
                ('warning', INCIDENT_PRIORITY_MODERATE),
                ('info', INCIDENT_PRIORITY_LOW),
                ('none', INCIDENT_PRIORITY_PLANNING)
            ]
            # priority_mapping laden
            cursor.execute('SELECT order, impact, urgency, priority FROM priority_mapping ORDER BY order')
            rows = cursor.fetchall()
            if rows:
                self.priority_mapping = [(row[1], row[2], row[3]) for row in rows]
                logger.info("Loaded priority mapping from SQLite")
            else:
                logger.warning("No priority mapping in SQLite. Inserting and using default (deutsch).")
                cursor.executemany('''
                    INSERT INTO priority_mapping (order, impact, urgency, priority)
                    VALUES (?, ?, ?, ?)
                ''', default_priority_mapping)
                self.priority_mapping = [(impact, urgency, priority) for _, impact, urgency, priority in default_priority_mapping]
            # severity_to_priority laden
            cursor.execute('SELECT severity, priority FROM severity_to_priority')
            rows = cursor.fetchall()
            if rows:
                self.severity_to_priority = {row[0]: row[1] for row in rows}
                logger.info("Loaded severity-to-priority mapping from SQLite")
            else:
                logger.warning("No severity-to-priority mapping in SQLite. Inserting and using default.")
                cursor.executemany('''
                    INSERT INTO severity_to_priority (severity, priority)
                    VALUES (?, ?)
                ''', default_severity_mapping)
                self.severity_to_priority = {severity: priority for severity, priority in default_severity_mapping}
            conn.commit()

    def get_urgency_impact_for_priority(self, target_priority):
        """Sucht die erste Zeile in priority_mapping mit der gewünschten priority."""
        logger = logging.getLogger(self.logger_name)
        for impact, urgency, priority in self.priority_mapping:
            if priority == target_priority:
                logger.debug(f"Found impact={impact}, urgency={urgency} for priority={target_priority}")
                return str(impact), str(urgency)  # Als String für API
        logger.warning(f"No matching impact/urgency found for priority={target_priority}, event_topic={event_topic}. Using defaults.")
        return INCIDENT_IMPACT_LOW, INCIDENT_URGENCY_LOW

    def check_number_exists(self, number, current_event_topic):
        """Prüft, ob a number scho in incidents existiert, unabhängig von archived."""
        logger = logging.getLogger(self.logger_name)
        with sqlite3.connect(os.environ["OMD_ROOT"] + "/var/tmp/svcnow.db") as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT event_topic, archived FROM incidents WHERE number = ?', (number,))
            result = cursor.fetchone()
            if result:
                event_topic, archived = result
                logger.critical(f"Number {number} already exists for event_topic {event_topic} (archived={archived}), cannot use for current_event_topic {current_event_topic}. Action: Attempted to create new incident.")
                return event_topic
            return None

    def submit(self, event):
        if isinstance(event, list):
            for one_event in event:
                if not self.submit_one(one_event):
                    return False
            return True
        else:
            success = self.submit_one(event)
            return True if event.is_heartbeat else success

    def submit_one(self, event):
        logger = logging.getLogger(self.logger_name)
        request_params = {
            "auth": requests.auth.HTTPBasicAuth(self.username, self.password) if self.username and self.password else None,
            "verify": False if self.insecure == "yes" else True,
            "headers": {"Content-type": "application/json"}
        }

        event_topic = getattr(event, "event_topic", None)
        if not event_topic:
            logger.critical(f"No event_topic provided in event. Action: Attempted to process event.")
            return False
        # Clean the topic from special characters
        event_topic = urllib.parse.quote(str(event_topic).lower())
        if len(event_topic) > 255:
            logger.critical(f"event_topic too long (>255 chars): {event_topic[:50]}..., event_topic={event_topic}. Action: Attempted to process event.")
            return False

        severity = getattr(event, "severity", "critical")
        status = getattr(event, "status", "firing")
        is_bad = (severity in ("critical", "warning") and status == "firing")
        is_harmless = (severity in ("info", "none") or status == "resolved")
        auto_close = getattr(event, "auto_close", True)  # Standard: True

        payload_compare = {
            "cmdb_ci": event.payload.get("cmdb_ci", "-CI-"),
            "business_service": event.payload.get("business_service", "-BS-"),
            "assignment_group": event.payload.get("assignment_group", "-AS-"),
            "severity": severity,
            "status": status,
        }
        payload_hash = hashlib.sha256(json.dumps(payload_compare, sort_keys=True).encode()).hexdigest()

        payload = event.payload.copy()
        payload.update({
            "caller_id": "Monitoring_Alert",
            "u_affected_user": "Monitoring_Alert",
            "contact_type": "Monitoring"
        })

        # Severity → Priority → Urgency/Impact
        target_priority = self.severity_to_priority.get(severity, INCIDENT_PRIORITY_MODERATE)  # Default: INCIDENT_PRIORITY_MODERATE
        payload["impact"], payload["urgency"] = self.get_urgency_impact_for_priority(target_priority)

        ticket_data = self.lookup_ticket(event.event_topic)
        if not ticket_data:
            logger.debug(f"No incident in db for event_topic={event.event_topic}")
            if is_bad:
                request_params["json"] = payload
                response = requests.post(self.url, **request_params)
                if response.status_code in [200, 201]:
                    sys_id = response.json()["result"]["sys_id"]
                    number = response.json()["result"]["number"]
                    conflicting_topic = self.check_number_exists(number, event.event_topic)
                    if conflicting_topic:
                        logger.critical(f"Cannot create incident: number {number} already used for conflicting_event_topic={conflicting_topic}, current_event_topic={event.event_topic}. Action: Attempted to create new incident.")
                        return False
                    self.upsert_record(event.event_topic, sys_id, number, severity, status, payload_hash)
                    browser_url = self.url.replace("/api/now/table/incident", f"/now/nav/ui/classic/params/target/incident.do%3Fsys_id%3D{sys_id}")
                    logger.info(f"Created new incident: {number} at {browser_url}, event_topic={event.event_topic}")
                    return True
                else:
                    logger.critical(f"POST failed for event_topic={event.event_topic}: {response.status_code} {response.text}. Action: Attempted to create new incident.")
                    return False
            else:
                logger.info(f"Harmless alert ignored: {event.summary}, event_topic={event.event_topic}")
                return True
        else:
            logger.debug(f"Found incident {ticket_data['number']} in db for event_topic={event.event_topic}")

            patch_url = f"{self.url}/{ticket_data['sys_id']}"
            response = requests.get(patch_url, **request_params)
            if response.status_code != 200:
                logger.critical(f"Could not fetch ticket {ticket_data['number']} for event_topic={event.event_topic}: {response.text}. Action: Attempted to retrieve incident state.")
                return False
            sn_state = response.json()["result"]["state"]

            if is_harmless:
                if sn_state in (INCIDENT_STATE_IN_PROGRESS, INCIDENT_STATE_RESOLVED, INCIDENT_STATE_CLOSED, INCIDENT_STATE_CANCELLED):
                    # Nur work_notes setzen, kein Status-Update
                    payload = {"work_notes": f"Monitoring-Update: Der Fehler besteht nicht mehr (severity={severity}, status={status})."}
                    request_params["json"] = payload
                    response = requests.patch(patch_url, **request_params)
                    if response.status_code == 200:
                        logger.info(f"Added work_notes to incident {ticket_data['number']} (state={sn_state}), event_topic={event.event_topic}")
                        logger.info(f"Archived incident {ticket_data['number']} for event_topic={event.event_topic} to allow new incident on next is_bad alert")
                        self.archive_record(event.event_topic)
                        return True
                    else:
                        logger.warning(f"Failed to add work_notes to incident {ticket_data['number']} for event_topic={event.event_topic}: {response.status_code} {response.text}. Action: Attempted to add work_notes.")
                        if response.status_code == 403:
                            logger.warning(f"ACL restriction detected, likely manually closed or restricted, skipping update for incident {ticket_data['number']} (state={sn_state}), event_topic={event.event_topic}. Action: Attempted to add work_notes.")
                            logger.info(f"Archived incident {ticket_data['number']} for event_topic={event.event_topic} to allow new incident on next is_bad alert")
                            self.archive_record(event.event_topic)
                            return True  # Fallback: Fortfahren trotz 403
                        logger.critical(f"Comment failed for incident {ticket_data['number']} for event_topic={event.event_topic}: {response.status_code} {response.text}. Action: Attempted to add work_notes.")
                        return False

                # Nur bei NEW oder ON_HOLD auf RESOLVED/CLOSED setzen
                if sn_state in (INCIDENT_STATE_NEW, INCIDENT_STATE_ON_HOLD):
                    payload["state"] = INCIDENT_STATE_RESOLVED
                    payload["close_code"] = "Resolved by caller"
                    payload["close_notes"] = f"Resolved by Alertmanager: {event.payload['short_description']}"
                    request_params["json"] = payload
                    response = requests.patch(patch_url, **request_params)
                    if response.status_code == 200:
                        logger.info(f"Resolved and archived incident {ticket_data['number']} for event_topic={event.event_topic}")
                        self.archive_record(event.event_topic)
                        if auto_close:
                            payload["state"] = INCIDENT_STATE_CLOSED
                            payload["close_code"] = "Closed by caller"
                            payload["close_notes"] = f"Closed by Gateway: {event.payload['short_description']}"
                            request_params["json"] = payload
                            response = requests.patch(patch_url, **request_params)
                            if response.status_code == 200:
                                logger.info(f"Closed incident {ticket_data['number']} for event_topic={event.event_topic}")
                                return True
                            else:
                                logger.critical(f"PATCH Close failed for incident {ticket_data['number']} for event_topic={event.event_topic}: {response.status_code} {response.text}. Action: Attempted to set incident to CLOSED.")
                                return False
                        logger.info(f"Resolved incident {ticket_data['number']} for event_topic={event.event_topic} without closing")
                        return True
                    else:
                        logger.critical(f"PATCH Resolve failed for incident {ticket_data['number']} for event_topic={event.event_topic}: {response.status_code} {response.text}. Action: Attempted to set incident to RESOLVED.")
                        return False
                else:
                    # Für RESOLVED, CLOSED, CANCELLED: Kein Status-Update, nur work_notes (bereits oben behandelt)
                    logger.info(f"Skipping status update for incident {ticket_data['number']} (state={sn_state}, already resolved or closed), event_topic={event.event_topic}")
                    logger.info(f"Archived incident {ticket_data['number']} for event_topic={event.event_topic} to allow new incident on next is_bad alert")
                    self.archive_record(event.event_topic)
                    return True

            elif is_bad:
                if sn_state in (INCIDENT_STATE_RESOLVED, INCIDENT_STATE_CLOSED, INCIDENT_STATE_CANCELLED):
                    # Altes Ticket archivieren und neues erstellen
                    logger.info(f"Incident {ticket_data['number']} is in state {sn_state}, archiving and creating new incident for event_topic={event.event_topic}")
                    self.archive_record(event.event_topic)
                    request_params["json"] = payload
                    response = requests.post(self.url, **request_params)
                    if response.status_code in [200, 201]:
                        sys_id = response.json()["result"]["sys_id"]
                        number = response.json()["result"]["number"]
                        conflicting_topic = self.check_number_exists(number, event.event_topic)
                        if conflicting_topic:
                            logger.critical(f"Cannot create incident: number {number} already used for conflicting_event_topic={conflicting_topic}, current_event_topic={event.event_topic}. Action: Attempted to create new incident.")
                            return False
                        self.upsert_record(event.event_topic, sys_id, number, severity, status, payload_hash)
                        ogger.info(f"Created new incident after archiving old one: {number}/{sys_id}, event_topic={event.event_topic}")
                        return True
                    else:
                        logger.critical(f"POST failed for event_topic={event.event_topic}: {response.status_code} {response.text}. Action: Attempted to create new incident.")
                        return False
                else:
                    # Offenes Ticket: Update oder ignorieren
                    if (ticket_data["severity"] == severity and
                        ticket_data["status"] == status and
                        ticket_data["payload_hash"] == payload_hash):
                        logger.info(f"Alert unchanged, skipping update for incident {ticket_data['number']}, event_topic={event.event_topic}")
                        return True
                    request_params["json"] = payload
                    response = requests.patch(patch_url, **request_params)
                    if response.status_code == 200:
                        self.upsert_record(event.event_topic, ticket_data["sys_id"], ticket_data["number"], severity, status, payload_hash)
                        logger.info(f"Updated incident {ticket_data['number']} for event_topic={event.event_topic}")
                        return True
                    else:
                        logger.critical(f"PATCH failed for incident {ticket_data['number']} for event_topic={event.event_topic}: {response.status_code} {response.text}. Action: Attempted to update incident.")
                        return False

            logger.critical(f"Unhandled case: state={sn_state}, severity={severity}, status={status}, event_topic={event.event_topic}. Action: Attempted to process event.")
            return False

    def upsert_record(self, event_topic, sys_id, number, severity, status, payload_hash):
        with sqlite3.connect(os.environ["OMD_ROOT"]+"/var/tmp/svcnow.db") as conn:
            conn.execute('pragma trusted_schema=ON;')
            conn.execute('pragma journal_mode=wal;')
            cursor = conn.cursor()
            query = '''
            INSERT INTO incidents (event_topic, sys_id, number, severity, status, payload_hash, created_at, updated_at, archived)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
            ON CONFLICT(event_topic) DO UPDATE SET
                sys_id = excluded.sys_id,
                number = excluded.number,
                severity = excluded.severity,
                status = excluded.status,
                payload_hash = excluded.payload_hash,
                updated_at = excluded.updated_at,
                archived = 0
            '''
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute(query, (event_topic, sys_id, number, severity, status, payload_hash, current_time, current_time))
            conn.commit()

    def lookup_ticket(self, event_topic):
        result = None
        with sqlite3.connect(os.environ["OMD_ROOT"]+"/var/tmp/svcnow.db") as conn:
            cursor = conn.cursor()
            query = '''
            SELECT * FROM incidents WHERE archived = 0 AND event_topic = ?
            '''
            cursor.execute(query, (event_topic,))
            result = cursor.fetchone()
        if result:
            columns = [column[0] for column in cursor.description]
            return dict(zip(columns, result))
        return result

    def archive_record(self, event_topic):
        with sqlite3.connect(os.environ["OMD_ROOT"]+"/var/tmp/svcnow.db") as conn:
            conn.execute('pragma trusted_schema=ON;')
            conn.execute('pragma journal_mode=wal;')
            cursor = conn.cursor()
            query = '''
            UPDATE incidents SET archived = 1, updated_at = ? WHERE event_topic = ?
            '''
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute(query, (current_time, event_topic))
            conn.commit()
