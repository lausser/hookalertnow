#! /usr/bin/python3

import os
import logging
import json
import signal
import sys
import sqlite3
from datetime import datetime, timedelta
from http import HTTPStatus
import requests
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
import csv
from io import StringIO

from bottle import Bottle, request, response, run
from wsgiref.simple_server import make_server

try:
    from notificationforwarder import baseclass
    from coshsh.util import setup_logging
except ImportError as e:
    logging.basicConfig()
    logging.critical(f"Required module missing: {e}")
    sys.exit(1)

logger = logging.getLogger("hookalertnow")



class OMDCGIError(Exception):
    def __init__(self, message, status_code):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

class OMDInMaintenance(OMDCGIError):
    pass


class OMDAuthBearer:
    def __init__(self, token):
        self.token = token if token else "default//forbidden"

    def verify(self, token):
        return bool(token and self.token == token)



class HookAlertNowApp:
    def __init__(self, write_token, servicenow_url, servicenow_username, servicenow_password):
        self.app = Bottle()
        self.logger = self._configure_logging()
        self.write_token = write_token
        self.svcnow_database_file = os.environ["OMD_ROOT"] + "/var/tmp/svcnow.db"
        self.maintenance_flag_file = os.environ["OMD_ROOT"] + "/var/tmp/hookalertnow_in_maintenance"
        self.servicenow_url = servicenow_url
        self.servicenow_username = servicenow_username
        self.servicenow_password = servicenow_password
        #self._setup_svcnow_database()
        #self._load_priority_mapping()
        self.forwarder = self._setup_forwarder(servicenow_url, servicenow_username, servicenow_password)
        self._setup_routes()

    def _configure_logging(self):
        if "OMD_ROOT" not in os.environ:
            os.environ["OMD_ROOT"] = os.environ.get("DOCUMENT_ROOT", "").replace("/var/www", "")
        os.environ["OMD_SITE"] = os.path.basename(os.environ["OMD_ROOT"])

        if not os.environ["OMD_ROOT"].startswith("/omd/sites/"):
            logger.critical("This script must be run in an OMD environment")
            sys.exit(1)

        scrnloglevel = logging.DEBUG if sys.stdin.isatty() else logging.CRITICAL
        setup_logging(
            logdir=os.environ["OMD_ROOT"] + "/var/log/hookalertnow",
            logfile="hookalertnow.log",
            scrnloglevel=scrnloglevel,
            txtloglevel=logging.INFO,
            format="[%(asctime)s][%(process)d] - %(levelname)s - %(message)s"
        )
        return logger

    def _setup_forwarder(self, url, username, password):
        try:
            forwarder_name = "hookalertnow"
            forwarder_tag = "hookalertnow"
            forwarder_opts = {
                "url": url,
                "username": username,
                "password": password,
                "insecure": "yes",
            }
            formatter_name = "hookalertnow"
            return baseclass.new(forwarder_name, None, formatter_name, True, True, forwarder_opts, None, None)
        except Exception as e:
            logger_name = f"notificationforwarder_{forwarder_name}_{forwarder_tag if forwarder_tag else ''}"
            self.logger.critical(f"Failed to initialize forwarder: {e}")
            self.logger.critical(f"No class for forwarder {forwarder_name} and formatter {formatter_name}")
            raise OMDCGIError(f"Forwarder setup error: {e}", 500)
        self.logger.info("Initialized forwarder")

    def _authenticate(self):
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            self.logger.debug("Extracted Bearer Token")
        else:
            self.logger.critical("No Bearer Token found in Authorization header")
            raise OMDCGIError("Authentication failed: No Bearer Token found", 401)

        if self.write_token is None:
            self.logger.critical("Write token not configured")
            raise OMDCGIError("Authentication failed: Write token not configured", 500)

        expected_token = OMDAuthBearer(self.write_token)
        if not expected_token.verify(token):
            self.logger.warning("Invalid token")
            raise OMDCGIError("Authentication failed: Invalid token", 401)

        return True

    def _handle_request(self, params):
        try:
            import pprint
            #self.logger.warning(json.dumps(params))
            pprint.pprint(params)
            # ggf group labels und annotations 
            # an den einzelnen alarm haengen
            self.forwarder.forward_multiple(params)
            return {'forwarder': f'forwarded or spooled alerts'}
        except Exception as e:
            raise OMDCGIError(f"Forwarding error: {e}", 500)

    def _setup_svcnow_database(self):
        with sqlite3.connect(self.svcnow_database_file) as conn:
            cursor = conn.cursor()
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                -- a combination of labels/eventopts (set in the formatter)
                -- which identifies a unique problem.
                event_topic TEXT PRIMARY KEY,
                sys_id TEXT NOT NULL,
                number TEXT NOT NULL UNIQUE,
                -- the severity of the alarm at the time
                -- when the incident was 1st created.
                severity TEXT,
                status TEXT,
                payload_hash TEXT,  -- Neu: Hash für Vergleich
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                archived INTEGER DEFAULT 0
            )
            ''')
            conn.commit()

    def _load_priority_mapping(self):
        logger = logging.getLogger("hookalertnow")
        base_url = self.servicenow_url.replace("/api/now/table/incident", "")
        mapping_url = f"{base_url}/dl_u_priority_list.do?sysparm_query=&CSV="
        request_params = {
            "auth": requests.auth.HTTPBasicAuth(self.servicenow_username, self.servicenow_password),
            "verify": False,
            "headers": {"Content-type": "text/csv"}
        }
        
        try:
            response = requests.get(mapping_url, **request_params, timeout=10)
            if response.status_code == 200:
                csv_content = response.text
                self._parse_and_store_mapping(csv_content)
                logger.info("Successfully loaded priority mapping from ServiceNow")
            else:
                logger.warning(f"Failed to fetch mapping: {response.status_code}. Will rely on SQLite.")
        except Exception as e:
            logger.error(f"Error fetching mapping: {e}. Will rely on SQLite.")

    def _parse_and_store_mapping(self, csv_content):
        logger = logging.getLogger("hookalertnow")
        conn = sqlite3.connect(self.svcnow_database_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS priority_mapping (
                impact TEXT,
                urgency TEXT,
                priority TEXT,
                updated_at TEXT
            )
        ''')
        
        csv_file = StringIO(csv_content)
        reader = csv.DictReader(csv_file)
        
        for row in reader:
            impact = row["impact"].split()[0]  # "1 - High" → "1"
            urgency = row["urgency"].split()[0]  # "1 - High" → "1"
            priority = row["priority"].split()[0]  # "1 - Critical" → "1"
            
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute('INSERT OR REPLACE INTO priority_mapping (impact, urgency, priority, updated_at) VALUES (?, ?, ?, ?)',
                          (impact, urgency, priority, current_time))
        
        conn.commit()
        conn.close()
        logger.debug("Stored priority mapping in SQLite")


    def _setup_routes(self):
        @self.app.route('/maintenance', method=['POST'])
        def handle_maintenance_request():
            originating_ip = request['REMOTE_ADDR']
            self.logger.info(f"Incoming maintenance request from {originating_ip}")
    
            # Nur von localhost erlauben
            if originating_ip != "127.0.0.1":
                response.status = 403
                response.headers['Content-Type'] = 'application/json'
                return json.dumps({"success": False, "error": "Maintenance can only be set from 127.0.0.1"})
    
            # Minuten aus dem Request holen
            minutes = request.forms.get("minutes") or request.json.get("minutes") if request.json else None
            if not minutes or not str(minutes).isdigit() or int(minutes) <= 0:
                response.status = 400
                response.headers['Content-Type'] = 'application/json'
                return json.dumps({"success": False, "error": "Invalid or missing 'minutes' parameter"})
    
            # Maintenance-Flag setzen
            self._create_maintenance_flag(minutes)
            response.status = 200
            response.headers['Content-Type'] = 'application/json'
            return json.dumps({"success": True, "answer": f"Maintenance mode activated for {minutes} minutes"})

        @self.app.route('/hello', method=['GET'])
        @self.app.route('/', method=['GET'])
        def handle_hello_request():
            originating_ip = request['REMOTE_ADDR']
            self.logger.info(f"Incoming hello request from {originating_ip}")
            try:
                self._check_maintenance()  # Exception hier, wenn Maintenance aktiv
                response.headers['Content-Type'] = 'application/json'
                response.status = 200
                return json.dumps({"success": True, "answer": f"hi there, {originating_ip}"})

            except OMDInMaintenance as e:
                response.status = e.status_code
                response.headers['Content-Type'] = 'application/json'
                return json.dumps({"success": False, "error": e.message})

            except OMDCGIError as e:
                self.logger.info("Error processing hello request")
                response.status = e.status_code
                response.headers['Content-Type'] = 'application/json'
                return json.dumps({"success": False, "error": e.message})

            except Exception as e:
                self.logger.exception("Unexpected error in hello request")
                response.status = 500
                response.headers['Content-Type'] = 'application/json'
                return json.dumps({"success": False, "error": str(e)})


        @self.app.route('/forward', method=['GET', 'POST'])
        def handle_forward_request():
            originating_ip = request['REMOTE_ADDR']
            self.logger.info(f"Incoming {request.method} request from {originating_ip}")
            try:
                self._authenticate()  # Will raise an exception if authentication fails
                self._check_maintenance()  # Exception hier, wenn Maintenance aktiv
                if request.method == 'GET':
                    params = request.query
                elif request.method == 'POST':
                    content_type = request.headers.get('Content-Type', '')
                    if 'application/json' in content_type:
                        params = request.json
                    elif 'application/x-www-form-urlencoded' in content_type:
                        # Fallback if the content type is incorrect
                        params = request.forms
                    else:
                        raise OMDCGIError(f"Unsupported Content-Type {content_type}", 415)
                else:
                    response.status = 405
                    response.headers['Content-Type'] = 'application/json'
                    return json.dumps({"success": False, "reason": f"method {request.method}"})

                ret = self._handle_request(params)
                result = {"success": True}
                result.update(ret)
                response.headers['Content-Type'] = 'application/json'
                return json.dumps(result)

            except OMDInMaintenance as e:
                response.status = e.status_code
                response.headers['Content-Type'] = 'application/json'
                return json.dumps({"success": False, "error": e.message})

            except OMDCGIError as e:
                self.logger.info("Error processing request")
                response.status = e.status_code
                response.headers['Content-Type'] = 'application/json'
                return json.dumps({"success": False, "error": e.message})

            except Exception as e:
                self.logger.exception("Unexpected error")
                response.status = 500
                response.headers['Content-Type'] = 'application/json'
                return json.dumps({"success": False, "error": str(e)})

        @self.app.route('/exporter', method=['GET'])
        def handle_exporter_request():
            hostname = os.uname().nodename
            now = datetime.now()
            total_seconds = now.minute * 60 + now.second
            cycle_position = total_seconds % 900
            simulated_cpu_usage = 10 + (cycle_position / 900) * 60
            metrics = f"""
# HELP simulated_cpu_usage Simulated CPU usage percentage
# TYPE simulated_cpu_usage gauge
simulated_cpu_usage{{instance="{hostname}"}} {simulated_cpu_usage:.2f}
"""
            response.content_type = 'text/plain; charset=utf-8'
            return metrics

    def _create_maintenance_flag(self, minutes):
        expiry = datetime.now() + timedelta(minutes=int(minutes))
        data = {"expiry": expiry.strftime("%Y-%m-%d %H:%M:%S")}
        with open(self.maintenance_flag_file, "w") as f:
            json.dump(data, f)
        self.logger.info(f"Maintenance mode activated until {expiry}")
    
    def _is_maintenance_active(self):
        if not os.path.exists(self.maintenance_flag_file):
            return False
        try:
            with open(self.maintenance_flag_file, "r") as f:
                data = json.load(f)
                expiry = datetime.strptime(data.get("expiry"), "%Y-%m-%d %H:%M:%S")
                if datetime.now() > expiry:
                    os.remove(self.maintenance_flag_file)  # Auto-Cleanup
                    self.logger.info("Maintenance mode expired and flag removed")
                    return False
                return True
        except (json.JSONDecodeError, ValueError) as e:
            self.logger.warning(f"Invalid maintenance flag file: {e}, treating as inactive")
            os.remove(self.maintenance_flag_file)
            return False

    def _check_maintenance(self):
        if self._is_maintenance_active():
            self.logger.info("Request blocked due to active maintenance mode")
            raise OMDInMaintenance("Service under maintenance", 503)


# --- Signal Handler for CTRL-C and omd stop ---
def sigterm_handler(signal, frame):
    logger = logging.getLogger("hookalertnow")
    logger.info(f"Received signal {signal}, shutting down...")
    sys.exit(0)

signal.signal(signal.SIGTERM, sigterm_handler)
signal.signal(signal.SIGINT, sigterm_handler)


if __name__ == '__main__':
    HOOKALERTNOW_WRITE_TOKEN = os.environ.get("HOOKALERTNOW_WRITE_TOKEN")
    SERVICENOW_INCIDENT_URL = os.environ.get("SERVICENOW_INCIDENT_URL")
    SERVICENOW_USERNAME = os.environ.get("SERVICENOW_USERNAME")
    SERVICENOW_PASSWORD = os.environ.get("SERVICENOW_PASSWORD")

    app_instance = HookAlertNowApp(
        HOOKALERTNOW_WRITE_TOKEN,
        SERVICENOW_INCIDENT_URL,
        SERVICENOW_USERNAME,
        SERVICENOW_PASSWORD
    )

    if 'HTTP_USER_AGENT' not in os.environ.keys():
        try:
            # Log startup message
            app_instance.logger.info("Starting AlertNowHookApp with Waitress server (not in CGI mode)...")
            
            # Run the Bottle app with Waitress
            run(app=app_instance.app, server="waitress", host='0.0.0.0', port=8080)
        except KeyboardInterrupt:
            app_instance.logger.info("Keyboard interrupt received, shutting down...")
        except SystemExit:
            app_instance.logger.info("System exit received, shutting down...")
        finally:
            # Log shutdown message
            app_instance.logger.info("AlertNowHookApp has been stopped.")
    else:
        # Running in CGI mode
        pass
