#!/usr/bin/env python3
# coding:utf-8

from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import logging

HOST = '0.0.0.0'
PORT = 8080

# Suspicious indicators of Spring4Shell
BLOCKED_PARAMS = [
    "class.module.classLoader.resources.context.parent.pipeline.first",
    "Runtime.getRuntime().exec",
    "tomcatwar.jsp"
]

BLOCKED_HEADERS = [
    "suffix", "c1", "c2"
]

class FirewallHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')

        # Check for malicious headers
        for header in BLOCKED_HEADERS:
            if header in self.headers:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Blocked: Suspicious header detected.")
                logging.warning(f"Blocked request with suspicious header: {header}")
                return

        # Check for malicious payload in POST data
        for pattern in BLOCKED_PARAMS:
            if pattern in post_data:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Blocked: Suspicious payload detected.")
                logging.warning(f"Blocked request with suspicious parameter: {pattern}")
                return

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Request allowed.")

def run(server_class=HTTPServer, handler_class=FirewallHTTPRequestHandler):
    logging.basicConfig(level=logging.INFO)
    server_address = (HOST, PORT)
    httpd = server_class(server_address, handler_class)
    logging.info(f'Starting firewall server on {HOST}:{PORT}')
    httpd.serve_forever()

if __name__ == '__main__':
    run()
