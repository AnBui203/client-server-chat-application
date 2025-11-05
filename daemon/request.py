#
# Copyright (C) 2025 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course.
#
# WeApRous release
#
# The authors hereby grant to Licensee personal permission to use
# and modify the Licensed Source Code for the sole purpose of studying
# while attending the course
#
import base64
import json as jsonlib
from urllib.parse import urlencode
"""
daemon.request
~~~~~~~~~~~~~~~~~

This module provides a Request object to manage and persist 
request settings (cookies, auth, proxies).
"""
from .dictionary import CaseInsensitiveDict

class Request():
    """The fully mutable "class" `Request <Request>` object,
    containing the exact bytes that will be sent to the server.

    Instances are generated from a "class" `Request <Request>` object, and
    should not be instantiated manually; doing so may produce undesirable
    effects.

    Usage::

      >>> import deamon.request
      >>> req = request.Request()
      ## Incoming message obtain aka. incoming_msg
      >>> r = req.prepare(incoming_msg)
      >>> r
      <Request>
    """
    __attrs__ = [
        "method",
        "url",
        "headers",
        "body",
        "reason",
        "cookies",
        "body",
        "routes",
        "hook",
    ]

    def __init__(self):
        #: HTTP verb to send to the server.
        self.method = None
        #: HTTP URL to send the request to.
        self.url = None
        #: dictionary of HTTP headers.
        self.headers = None
        #: HTTP path
        self.path = None
        #: Query parameters from URL
        self.query_params = {}
        # The cookies set used to create Cookie header
        self.cookies = None
        #: request body to send to the server.
        self.body = None
        #: Routes
        self.routes = {}
        #: Hook point for routed mapped-path
        self.hook = None

    # Ex: POST /login HTTP/1.1  -> method = POST, path = /login, version = HTTP/1.1
    def extract_request_line(self, request):
        try:
            lines = request.splitlines()
            first_line = lines[0]
            method, path, version = first_line.split()

            if path == '/':
                path = '/index.html'
        except Exception:
            return None, None, None

        return method, path, version
             


    """ Ex: [
                "GET /hello HTTP/1.1",
                "Host: localhost:8080",
                "User-Agent: curl/8.4.0",
                "Accept: */*",
                ""
            ]

            Bỏ qua dòng đầu -> Có ":" là header
            -> "Host: localhost:8080" -> key = "host", value = "localhost:8080"

            -> headers = {
                            "host": "localhost:8080",
                            "user-agent": "curl/8.4.0",
                            "accept": "*/*"
                          }
            -> headers là một dictionary (key viết chữ thường)
            """

    def prepare_headers(self, request):
        """Prepares the given HTTP headers."""
        lines = request.split('\r\n')
        headers = {}  # ??? dictionary.py???? có tác dụng gì?? dùng dictionary của python???
        for line in lines[1:]:
            if ': ' in line:
                key, val = line.split(': ', 1)
                headers[key.lower()] = val
        print(headers)
        return headers
    
    def prepare_request(self, request):
        # First line
        first_line = request.split('\r\n')[0]

        # Split headers and body using CRLF CRLF
        parts = request.split('\r\n\r\n', 1)
        header_block = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        # Parse header lines (stop at blank line)
        header_lines = header_block.split('\r\n')
        headers = {}
        # header_lines[0] is the request line
        for line in header_lines[1:]:
            if ': ' in line:
                key, val = line.split(': ', 1)
                headers[key.lower()] = val
        # Debug print
        print(headers)

        # Keep the raw body string. Higher-level handlers will parse JSON if needed.
        self.body = body

        return first_line, headers, body



    def prepare(self, request, routes=None):
        """Prepares the entire request with the given parameters."""

        # Prepare the request line from the request header
        self.method, self.path, self.version = self.extract_request_line(request)
        
        # Parse query parameters from path
        if '?' in self.path:
            path_part, query_part = self.path.split('?', 1)
            self.path = path_part
            # Parse query string: key1=value1&key2=value2
            from urllib.parse import parse_qs
            parsed = parse_qs(query_part)
            # parse_qs returns lists, flatten to single values
            self.query_params = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
        else:
            self.query_params = {}
        
        print("[Request] {} path {} version {}".format(self.method, self.path, self.version))
        if self.query_params:
            print("[Request] Query params: {}".format(self.query_params))
        """ "GET /hello HTTP/1.1" -> [Request] GET path /hello version HTTP/1.1  """
        
        if not routes == {}:
            self.routes = routes
            self.hook = routes.get((self.method, self.path))

        _ ,self.headers ,self.body = self.prepare_request(request)
        # self.headers = self.prepare_headers(request)
        cookies = self.headers.get('cookie', '') # tức là header có 1 key = "cookie"
        self.cookies = self.prepare_cookies(cookies)
            #
            #  xTODO:implement the cookie function here
            #        by parsing the header            #
        print("Method: ", self.method)
        print("URL: ", self.url)
        print("Headers: ", self.headers)
        print("Body: ", self.body)
        print("Path: ", self.path)
        print("Cookies: ", self.cookies)
        print("Routes: {} hook: {}".format(self.routes, self.hook))
        return

    def prepare_body(self, json, data, files):
        # self.prepare_content_length(self.body)
        # self.body = body
        #
        # xTODO prepare the request authentication
        #

        # body = request.split('\r\n\r\n')[1] 
        if json is not None:
            import json as jsonlib
            body = jsonlib.dumps(json)
            self.headers["Content-Type"] = "application/json"
        elif data is not None:
            # Encode data as x-www-form-urlencoded
            from urllib.parse import urlencode
            body = urlencode(data)
            self.headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif files is not None:
            # TODO: handle multipart in more advanced version
            body = files
            self.headers["Content-Type"] = "multipart/form-data"
        else:
            body = ""

        self.body = body
        self.prepare_content_length(body)
        return self
	# self.auth = ...
        return


    def prepare_content_length(self, body):
        # self.headers["Content-Length"] = "0"
        #
        # xTODO prepare the request authentication
        #
        if body is None:
            length = 0
        else:
            length = len(body.encode('utf-8')) if isinstance(body, str) else len(body)
        self.headers["Content-Length"] = str(length)
        return self
	# self.auth = ...
        # return


    def prepare_auth(self, auth, url=""):
        #
        # xTODO prepare the request authentication
        ## gpt 
        if auth and isinstance(auth, tuple) and len(auth) == 2:
            username, password = auth
            token = f"{username}:{password}".encode('utf-8')
            b64 = base64.b64encode(token).decode('utf-8')
            self.headers["Authorization"] = f"Basic {b64}"
        return self
	# self.auth = ...
        # return

    def prepare_cookies(self, cookies):
        # self.headers["Cookie"] = cookies
        # if cookies:
        #     cookie_str = '; '.join([f"{k}={v}" for k, v in cookies.items()])
        #     self.headers["Cookie"] = cookie_str
        # return self
        cookie_dict = {}
        if cookies:
            pairs = cookies.split(',')
            for pair in pairs:
                if '=' in pair:
                    key, value = pair.strip().split('=', 1)
                    cookie_dict[key] = value
        return cookie_dict