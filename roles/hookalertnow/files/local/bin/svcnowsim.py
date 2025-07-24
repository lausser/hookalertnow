#! /usr/bin/python3

import os
import logging
import json
import signal
import sys
from http import HTTPStatus

from bottle import Bottle, request, response
from wsgiref.simple_server import make_server

HOOKALERTNOW_WRITE_TOKEN = os.environ.get("HOOKALERTNOW_WRITE_TOKEN")
SERVICENOW_INCIDENT_URL = os.environ.get("SERVICENOW_INCIDENT_URL")
SERVICENOW_USERNAME = os.environ.get("SERVICENOW_USERNAME")
SERVICENOW_PASSWORD = os.environ.get("SERVICENOW_PASSWORD")
print(SERVICENOW_INCIDENT_URL)
print(SERVICENOW_USERNAME)
print(SERVICENOW_PASSWORD)
print(HOOKALERTNOW_WRITE_TOKEN)
try:
    from notificationforwarder import baseclass
    from coshsh.util import setup_logging
except ImportError as e:
    logging.basicConfig()
    logging.critical(f"Required module missing: {e}")
    sys.exit(1)

class OMDAuthBearer(object):
    def __init__(self, token):
        self.token = token if token else "default//forbidden"

    def verify(self, token):
        return bool(token and self.token == token)

def authenticate():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        logger.debug("Extracted Bearer Token")
    else:
        token = None
        logger.critical("No Bearer Token found in Authorization header")
        return False

    if HOOKALERTNOW_WRITE_TOKEN is None:
        logger.critical("Write token not configured")
        return False

    expected_token = OMDAuthBearer(HOOKALERTNOW_WRITE_TOKEN)
    if not expected_token.verify(token):
        logger.warning("Invalid token")
        return False
    return True



def configure_logging():
    logger = logging.getLogger("svcnowsim")
    if "OMD_ROOT" not in os.environ:
        os.environ["OMD_ROOT"] = os.environ.get("DOCUMENT_ROOT", "").replace("/var/www", "")
    os.environ["OMD_SITE"] = os.path.basename(os.environ["OMD_ROOT"])

    if not os.environ["OMD_ROOT"].startswith("/omd/sites/"):
        logger.critical("This script must be run in an OMD environment")
        sys.exit(1)

    scrnloglevel = logging.DEBUG if sys.stdin.isatty() else logging.CRITICAL
    setup_logging(
        logdir=os.environ["OMD_ROOT"] + "/var/log/svcnowsim",
        logfile="svcnowsim.log",
        scrnloglevel=scrnloglevel,
        txtloglevel=logging.INFO,
        format="[%(asctime)s][%(process)d] - %(levelname)s - %(message)s"
    )
    return logger

def setup_app():
    app = Bottle()

    @app.route('/api/now/table/incident', method=['GET', 'POST'])
    def handle_servicenow_request():
        originating_ip = request['REMOTE_ADDR']
        logger.info(f"Incoming {request.method} request from {originating_ip} to the servicenow simulator")

        if False and not authenticate():
            response.status = 401
            response.headers['Content-Type'] = 'application/json'
            return json.dumps({"success": False, "reason": "invalid token"})
    
        try:
            if request.method == 'GET':
                params = request.query  # Access GET parameters
            elif request.method == 'POST':
                content_type = request.headers.get('Content-Type', '')
                # Attempt to parse JSON, fallback to URL-encoded
                if 'application/json' in content_type:
                    params = request.json
                elif 'application/x-www-form-urlencoded' in content_type:
                    params = request.forms
                else:
                    raise ValueError("Unsupported Content-Type")
                    response.status = 415
                    response.headers['Content-Type'] = 'application/json'
                    return json.dumps({"success": False, "reason": "content is neither json nor params"})
                logger.debug("+++++servicenow+++++++")
                logger.debug(params)
                logger.debug("+++++servicenow+++++++")
            else:
                response.status = 405
                response.headers['Content-Type'] = 'application/json'
                return json.dumps({"success": False, "reason": f"method {request.method}"})
    
            result = {"success": True}
            response.headers['Content-Type'] = 'application/json'
            return json.dumps(result)
    
        except Exception as e:
            logger.exception("Error processing request")  # Log the full exception
            code = getattr(e, 'status_code', 500)  # Default to 500 if no status_code
            status_text = HTTPStatus(code).phrase
            response.status = code
            response.headers['Content-Type'] = 'application/json'
            result = {"success": False, "error": str(e)}
            return json.dumps(result)

    return app

# --- Signal Handler ---
httpd = None

def sigterm_handler(signal, frame):
    logger = logging.getLogger("svcnowsim")
    logger.info(f"Received signal {signal}, shutting down...")
    if httpd:
        httpd.server_close()
    sys.exit(0)

signal.signal(signal.SIGTERM, sigterm_handler)
signal.signal(signal.SIGINT, sigterm_handler)

if __name__ == '__main__':
    logger = configure_logging()
    app = setup_app()

    if 'HTTP_USER_AGENT' not in os.environ.keys():
        print("Running wsgiref server (not in CGI mode)")
        host, port = '0.0.0.0', 8081
        httpd = make_server(host, port, app)
        try:
            logger.info(f"Starting server on {host}:{port}")
            httpd.serve_forever()
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received, shutting down...")
            httpd.server_close()
    else:
        pass

