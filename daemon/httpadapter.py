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

"""
daemon.httpadapter
~~~~~~~~~~~~~~~~~

This module provides a http adapter object to manage and persist 
http settings (headers, bodies). The adapter supports both
raw URL paths and RESTful route definitions, and integrates with
Request and Response objects to handle client-server communication.
"""

import json
import socket
import hashlib
import time
from typing import Optional
from urllib.parse import parse_qs
from .request import Request
from .response import Response
from .dictionary import CaseInsensitiveDict
from .peer_tracker import PeerTracker
from .channel import Channel, Message, ChannelManager
from .auth import AuthManager, ResponseBuilder

# Use single, module-level instances so all adapter instances share state
_GLOBAL_PEER_TRACKER = PeerTracker()
_GLOBAL_CHANNEL_MANAGER = ChannelManager()
_GLOBAL_AUTH_MANAGER = AuthManager()

class HttpAdapter:
    """
    A mutable :class:`HTTP adapter <HTTP adapter>` for managing client connections
    and routing requests.

    The `HttpAdapter` class encapsulates the logic for receiving HTTP requests,
    dispatching them to appropriate route handlers, and constructing responses.
    It supports RESTful routing via hooks and integrates with :class:`Request <Request>` 
    and :class:`Response <Response>` objects for full request lifecycle management.

    Attributes:
        ip (str): IP address of the client.
        port (int): Port number of the client.
        conn (socket): Active socket connection.
        connaddr (tuple): Address of the connected client.
        routes (dict): Mapping of route paths to handler functions.
        request (Request): Request object for parsing incoming data.
        response (Response): Response object for building and sending replies.
    """

    __attrs__ = [
        "ip",
        "port",
        "conn",
        "connaddr",
        "routes",
        "request",
        "response",
    ]

    def __init__(self, ip, port, conn, connaddr, routes):
        """
        Initialize a new HttpAdapter instance.

        :param ip (str): IP address of the client.
        :param port (int): Port number of the client.
        :param conn (socket): Active socket connection.
        :param connaddr (tuple): Address of the connected client.
        :param routes (dict): Mapping of route paths to handler functions.
        """

        #: IP address.
        self.ip = ip
        #: Port.
        self.port = port
        #: Connection
        self.conn = conn
        #: Conndection address
        self.connaddr = connaddr
        #: Routes
        # Initialize routes dictionary
        self.routes = routes
        #: Request
        self.request = Request()
        #: Response
        self.response = Response()
        #: Peer tracker for managing chat peers (shared instance)
        self.peer_tracker = _GLOBAL_PEER_TRACKER
        #: Channel manager for chat channels (shared instance)
        self.channel_manager = _GLOBAL_CHANNEL_MANAGER
        self.auth_manager = _GLOBAL_AUTH_MANAGER
        
    def handle_client(self, conn: socket.socket, addr: tuple, routes: dict) -> None:
        """
        Handle an incoming client connection by processing HTTP requests and generating responses.

        This method is the main entry point for handling client connections. It:
        1. Reads and parses the HTTP request from the socket
        2. Handles authentication and session management
        3. Routes requests to appropriate handlers
        4. Generates and sends HTTP responses

        Args:
            conn: The client socket connection for sending/receiving data
            addr: The client's address as (ip, port) tuple
            routes: Dictionary mapping URL paths to handler functions

        Returns:
            None: All responses are sent directly through the socket connection

        Raises:
            socket.error: If there are network communication issues
            ValueError: If the request cannot be parsed
            Exception: For other unexpected errors during request handling

        Example:
            >>> sock, addr = server.accept()
            >>> adapter.handle_client(sock, addr, app_routes)
        """

        # Connection handler.
        self.conn = conn        
        # Connection address.
        self.connaddr = addr
        # Request handler
        req = self.request
        # Response handler
        resp = self.response

        # Handle the request
        try:
            msg = conn.recv(1024).decode('utf-8')
            if not msg:
                print("[HttpAdapter] Error: Empty request received")
                return conn.sendall(ResponseBuilder.bad_request("Empty request"))
        except socket.error as e:
            print(f"[HttpAdapter] Socket error receiving request: {str(e)}")
            return conn.sendall(ResponseBuilder.server_error("Network error"))
        except UnicodeDecodeError as e:
            print(f"[HttpAdapter] Decode error: {str(e)}")
            return conn.sendall(ResponseBuilder.bad_request("Invalid request encoding"))
            
        print("[HttpAdapter] Received request:", msg)
        
        # Initialize body as empty string
        body = ""
        
        # For POST requests, read the body based on Content-Length
        if "Content-Length: " in msg:
            try:
                content_length = int(msg.split("Content-Length: ")[1].split("\r\n")[0])
                if "\r\n\r\n" in msg:
                    body = msg.split("\r\n\r\n")[1]
                    remaining = content_length - len(body)
                    if remaining > 0:
                        try:
                            body += conn.recv(remaining).decode('utf-8')
                        except socket.error as e:
                            print(f"[HttpAdapter] Socket error reading body: {str(e)}")
                            return conn.sendall(ResponseBuilder.server_error("Error reading request body"))
            except (ValueError, IndexError) as e:
                print(f"[HttpAdapter] Error parsing Content-Length: {str(e)}")
                return conn.sendall(ResponseBuilder.bad_request("Invalid Content-Length"))
        
        try:
            req.prepare(msg, routes)
            if body.strip():  # Only set body if it's not empty
                req.body = body
        except Exception as e:
            print(f"[HttpAdapter] Error preparing request: {str(e)}")
            return conn.sendall(ResponseBuilder.bad_request("Invalid request format"))
            
        # Handle authentication endpoints
        if req.path == '/login' and req.method == 'POST':
            return self._handle_login(req)

        # Allow certain auth-related endpoints to be handled without authentication
        whitelist_no_auth = [
            # Auth endpoints
            '/login',
            '/login.html', 
            '/api/check-auth',
            '/api/connect'
        ]
        
        # Allow all static files and root HTML
        if req.path.startswith('/static/') or req.path == '/':
            whitelist_no_auth.append(req.path)
            
        # Special-case logout: handle before auth check to ensure smooth logout
        if req.path == '/logout':
            # attempt to clear session server-side if cookie present
            sid = self._get_auth_cookie(req)
            if sid:
                try:
                    self.auth_manager.logout(sid)
                except Exception:
                    pass
            # send redirect that clears cookie
            conn.sendall(ResponseBuilder.redirect_with_logout('/login.html'))
            conn.close()
            return

        # Handle chat endpoints first, as they have their own auth handling
        chat_endpoints = [
            '/register', '/peers', '/deregister', '/heartbeat',
            '/channels', '/channels/create', '/channels/join',
            '/channels/leave', '/channels/messages', '/api/check-auth', '/api/connect'
        ]
        if req.path in chat_endpoints:
            body_obj, status_code = self.handle_chat_endpoint(req)
            # Default status and reason
            status_code = status_code or 200
            reason = {
                200: 'OK',
                201: 'Created',
                400: 'Bad Request',
                401: 'Unauthorized',
                404: 'Not Found',
                500: 'Internal Server Error'
            }.get(status_code, 'OK')
            
            body_json = json.dumps(body_obj)
            headers = []
            headers.append(f"HTTP/1.1 {status_code} {reason}")
            headers.append("Content-Type: application/json")
            headers.append(f"Content-Length: {len(body_json.encode('utf-8'))}")
            headers.append("\r\n")
            response_bytes = ("\r\n".join(headers)).encode('utf-8') + body_json.encode('utf-8')
            conn.sendall(response_bytes)
            conn.close()
            return
            
        # For non-chat endpoints, check authentication (skip static and whitelisted endpoints)
        if not req.path.startswith('/static/') and req.path not in whitelist_no_auth:
            auth_cookie = self._get_auth_cookie(req)
            if not auth_cookie or not self.auth_manager.validate_session(auth_cookie):
                return conn.sendall(ResponseBuilder.unauthorized())

            body_json = json.dumps(body_obj)
            headers = []
            headers.append(f"HTTP/1.1 {status_code} {reason}")
            headers.append("Content-Type: application/json")
            headers.append(f"Content-Length: {len(body_json.encode('utf-8'))}")
            headers.append("\r\n")
            response_bytes = ("\r\n".join(headers)).encode('utf-8') + body_json.encode('utf-8')
            conn.sendall(response_bytes)
            conn.close()
            return

        # Handle standard route hooks
        if req.hook:
            print("[HttpAdapter] hook in route-path METHOD {} PATH {}".format(req.hook._route_path,req.hook._route_methods))
            req.hook(headers = "bksysnet",body = "get in touch")
            # req.
            #
            # TODO: handle for App hook here
            #
        # cookies = self.extract_cookies
        # is_authenticated = cookies.get('auth') == 'true'
        #     # Task 1A: Xử lý POST /login [cite: 176]
        # if req.path == '/login' and req.method == 'POST':
        #     # Giả sử body là "username=admin&password=password"
        #     # Cần có một hàm parse body tốt hơn, nhưng đây là logic cơ bản
        #     if 'username=admin' in req.body and 'password=password' in req.body:
        #         # Login đúng: Set cookie và trả về trang index 
        #         resp.headers['Set-Cookie'] = 'auth=true; Path=/'
        #         req.path = '/index.html' # Yêu cầu Response build trang index
        #     else:
        #         # Login sai: Trả về 401 
        #         response = self.build_notfound()
        #         conn.sendall(response)
        #         conn.close()
        #         return

        # # Task 1B: Kiểm tra truy cập các trang khác 
        # elif req.path != '/login' and not is_authenticated:
        #     # Nếu không phải trang login và chưa login -> 401 [cite: 182]
        #     # (Trừ các file tĩnh như CSS, JS. Tạm thời đơn giản hóa)
        #     if req.path.startswith('/static/') or req.path == '/':
        #         pass # Cho phép truy cập file tĩnh
        #     else:
        #         response = self.build_unauthorized()
        #         conn.sendall(response)
        #         conn.close()
        #         return

        # # Task 2: Xử lý WeApRous (Chat App) [cite: 194]
        # if req.hook:
        #     print("[HttpAdapter] hook in route-path METHOD {} PATH {}".format(req.method, req.path))
        #     # (Hoàn thiện TODO): Gọi hook với DỮ LIỆU THỰC TẾ
        #     hook_result = req.hook(headers=req.headers, body=req.body)
            
        #     # Gán kết quả trả về từ hook (vd: {'message': 'Hello'})
        #     # để Response biết và xây dựng body [cite: 718]
        #     resp.hook_data = str(hook_result) 
        #     resp.headers['Content-Type'] = 'application/json'
        # Build response
        response = resp.build_response(req)

        #print(response)
        conn.sendall(response)
        conn.close()

    @property
    def extract_cookies(self, req, resp):
        """
        Build cookies from the :class:`Request <Request>` headers.

        :param req:(Request) The :class:`Request <Request>` object.
        :param resp: (Response) The res:class:`Response <Response>` object.
        :rtype: cookies - A dictionary of cookie key-value pairs.
        """
        cookies = {}
        for header in req.headers:
            if header.startswith("Cookie:"):
                cookie_str = header.split(":", 1)[1].strip()
                for pair in cookie_str.split(";"):
                    key, value = pair.strip().split("=")
                    cookies[key] = value
        return cookies

    def handle_chat_endpoint(self, req):
        """
        Handle chat-related endpoints: /register, /peers, /deregister, /heartbeat,
        /channels, /channels/create, /channels/join, /channels/messages
        
        :param req: The Request object
        :return: Dictionary with response data
        """
        try:
            # Auth endpoints
            if req.path == '/api/check-auth' and req.method == 'GET':
                print("[API] Checking auth...")
                print("[API] Headers:", req.headers)
                sid = self._get_auth_cookie(req)
                print("[API] Found cookie:", sid)
                if sid:
                    is_valid = self.auth_manager.validate_session(sid)
                    print("[API] Session valid:", is_valid)
                    if is_valid:
                        session = self.auth_manager.sessions.get(sid)
                        username = session.user_id if session else None
                        return {"ok": True, "username": username}, 200
                return {"ok": False}, 401
                
            # Channel endpoints
            if req.path == '/channels' and req.method == 'GET':
                # Get current user ID from auth session
                sid = self._get_auth_cookie(req)
                if not sid or not self.auth_manager.validate_session(sid):
                    return {"error": "Unauthorized"}, 401
                session = self.auth_manager.sessions[sid]
                user_id = session.user_id

                # List available channels
                channels = self.channel_manager.list_channels(for_peer_id=user_id)
                return {
                    "channels": [{
                        "id": c.id,
                        "name": c.name,
                        "description": c.description,
                        "memberCount": len(c._members),
                        "isPrivate": c.is_private,
                        "createdBy": c.created_by
                    } for c in channels]
                }, 200
                
            if req.path == '/channels/create' and req.method == 'POST':
                try:
                    data = json.loads(req.body)
                except json.JSONDecodeError:
                    return {"error": "Invalid JSON"}, 400

                if not all(field in data for field in ['name', 'createdBy']):
                    return {"error": "Missing required fields"}, 400

                # Generate unique channel ID
                channel_id = hashlib.sha256(
                    f"{data['name']}:{time.time()}".encode()
                ).hexdigest()[:12]

                # Create channel
                channel = self.channel_manager.create_channel(
                    channel_id=channel_id,
                    name=data['name'],
                    created_by=data['createdBy'],
                    description=data.get('description', ''),
                    is_private=data.get('isPrivate', False),
                    allowed_members=data.get('allowedMembers', [])
                )

                if not channel:
                    return {"error": "Channel creation failed"}, 500

                return {
                    "channel": {
                        "id": channel.id,
                        "name": channel.name,
                        "description": channel.description,
                        "isPrivate": channel.is_private,
                        "createdBy": channel.created_by
                    }
                }, 201
                
            if req.path == '/channels/join' and req.method == 'POST':
                try:
                    data = json.loads(req.body)
                except json.JSONDecodeError:
                    return {"error": "Invalid JSON"}, 400

                if not all(field in data for field in ['channelId', 'userId']):
                    return {"error": "Missing required fields"}, 400

                # Get channel
                channel = self.channel_manager.get_channel(data['channelId'])
                if not channel:
                    return {"error": "Channel not found"}, 404

                # Get user info
                peer = self.peer_tracker.get_peer(data['userId'])
                if not peer:
                    return {"error": "User not registered"}, 400

                # Add member to channel
                if not channel.add_member(data['userId'], peer):
                    return {"error": "Failed to join channel"}, 400

                return {
                    "channel": {
                        "id": channel.id,
                        "name": channel.name,
                        "description": channel.description,
                        "members": list(channel.get_members().keys()),
                        "isPrivate": channel.is_private,
                        "createdBy": channel.created_by
                    }
                }, 200
            if req.path == '/api/connect' and req.method == 'GET':
                sid = self._get_auth_cookie(req)
                if sid and self.auth_manager.validate_session(sid):
                    return {"success": True}, 200
                else:
                    return {"success": False}, 401
            if req.path == '/register' and req.method == 'POST':
                # Parse request body as JSON
                try:
                    data = json.loads(req.body)
                except json.JSONDecodeError:
                    return {"error": "Invalid JSON"}, 400
                
                # Validate required fields
                required = ['id', 'ip', 'port']
                if not all(field in data for field in required):
                    return {
                        "error": "Missing required fields",
                        "required": required
                    }, 400
                
                # Register the peer
                success = self.peer_tracker.register_peer(
                    data['id'],
                    data['ip'],
                    data['port'],
                    data.get('meta', {})
                )
                
                if success:
                    return {
                        "status": "ok",
                        "expires_in": self.peer_tracker.ttl_seconds
                    }, 201
                else:
                    return {"error": "Registration failed"}, 400
            
            elif req.path == '/peers' and req.method == 'GET':
                # Optional exclude parameter (headers stored lowercased by Request.prepare)
                exclude_peer = req.headers.get('x-exclude-peer') or req.headers.get('X-Exclude-Peer')
                peers = self.peer_tracker.get_active_peers(exclude_peer)
                return {"peers": peers}, 200
            
            elif req.path == '/deregister' and req.method == 'POST':
                try:
                    data = json.loads(req.body)
                except json.JSONDecodeError:
                    return {"error": "Invalid JSON"}, 400
                
                if 'id' not in data:
                    return {"error": "Missing peer id"}, 400
                
                if self.peer_tracker.deregister_peer(data['id']):
                    return {"status": "ok"}, 200
                else:
                    return {"error": "Peer not found"}, 404
            
            elif req.path == '/heartbeat' and req.method == 'POST':
                try:
                    data = json.loads(req.body)
                except json.JSONDecodeError:
                    return {"error": "Invalid JSON"}, 400
                
                if 'id' not in data:
                    return {"error": "Missing peer id"}, 400
                
                if self.peer_tracker.update_peer_timestamp(data['id']):
                    return {"status": "ok"}, 200
                else:
                    return {"error": "Peer not found"}, 404
            
            elif req.path == '/relay' and req.method == 'POST':
                # Relay a message from a client (browser/UI) to a peer by opening a TCP connection
                try:
                    data = json.loads(req.body)
                except json.JSONDecodeError:
                    return {"error": "Invalid JSON"}, 400

                # required fields: to (peer id), message, from (optional)
                if 'to' not in data or 'message' not in data:
                    return {"error": "Missing 'to' or 'message'"}, 400

                to_id = data['to']
                message = data['message']
                from_id = data.get('from', '')

                # Lookup peer
                peers = self.peer_tracker.get_active_peers()
                target = None
                for p in peers:
                    if p['id'] == to_id:
                        target = p
                        break

                if not target:
                    return {"error": "Target peer not found or offline"}, 404

                # Try to open TCP to target and send JSON message
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3.0)
                    s.connect((target['ip'], int(target['port'])))
                    payload = {"type": "chat", "from": from_id, "to": to_id, "message": message}
                    s.sendall(json.dumps(payload).encode() + b'\n')
                    s.close()
                    return {"status": "relayed"}, 200
                except Exception as e:
                    print(f"[HttpAdapter] Relay failed: {e}")
                    return {"error": "Relay failed", "detail": str(e)}, 500
                    
            elif req.path == '/channels' and req.method == 'GET':
                # List available channels
                channels = []
                for channel in self.channel_manager.channels.values():
                    members = len(channel.get_members())
                    channels.append({
                        "id": channel.id,
                        "name": channel.name,
                        "description": channel.description,
                        "created_by": channel.created_by,
                        "is_private": channel.is_private,
                        "member_count": members
                    })
                return {"channels": channels}, 200
                
            elif req.path == '/channels/create' and req.method == 'POST':
                try:
                    data = json.loads(req.body)
                except json.JSONDecodeError:
                    return {"error": "Invalid JSON"}, 400
                    
                required = ['id', 'name', 'created_by']
                if not all(field in data for field in required):
                    return {"error": "Missing required fields"}, 400
                    
                channel = self.channel_manager.create_channel(
                    channel_id=data['id'],
                    name=data['name'],
                    created_by=data['created_by'],
                    description=data.get('description', ''),
                    is_private=data.get('is_private', False),
                    allowed_members=data.get('allowed_members', [])
                )
                
                if channel:
                    return {"status": "ok", "channel_id": channel.id}, 201
                else:
                    return {"error": "Channel creation failed"}, 400
                    
            elif req.path == '/channels/join' and req.method == 'POST':
                try:
                    data = json.loads(req.body)
                except json.JSONDecodeError:
                    return {"error": "Invalid JSON"}, 400
                    
                if 'channelId' not in data or 'userId' not in data:
                    return {"error": "Missing channelId or userId"}, 400
                    
                channel = self.channel_manager.get_channel(data['channelId'])
                if not channel:
                    return {"error": "Channel not found"}, 404
                    
                # Get peer info
                peer = None
                for p in self.peer_tracker.get_active_peers():
                    if p['id'] == data['peer_id']:
                        peer = p
                        break
                        
                if not peer:
                    return {"error": "Peer not found"}, 404
                                        
                if channel.add_member(data['peer_id'], peer):
                    return {
                        "status": "ok", 
                        "message": "Successfully joined channel",
                        "channel": {
                            "id": channel.id,
                            "name": channel.name,
                            "created_by": channel.created_by,
                            "description": channel.description,
                            "is_private": channel.is_private,
                            "allowed_members": channel.allowed_members
                        }
                    }, 200
                else:
                    return {"error": "Join failed"}, 400
                    
            elif req.path == '/channels/leave' and req.method == 'POST':
                try:
                    data = json.loads(req.body)
                except json.JSONDecodeError:
                    return {"error": "Invalid JSON"}, 400
                    
                if 'channel_id' not in data or 'peer_id' not in data:
                    return {"error": "Missing channel_id or peer_id"}, 400
                    
                channel = self.channel_manager.get_channel(data['channel_id'])
                if not channel:
                    return {"error": "Channel not found"}, 404
                    
                if channel.remove_member(data['peer_id']):
                    return {"status": "ok"}, 200
                else:
                    return {"error": "Leave failed"}, 400
                    
            elif req.path == '/channels/messages' and req.method == 'GET':
                channel_id = req.query_params.get('channel_id')
                since = req.query_params.get('since')
                
                if not channel_id:
                    return {"error": "Missing channel_id"}, 400
                    
                channel = self.channel_manager.get_channel(channel_id)
                if not channel:
                    return {"error": "Channel not found"}, 404
                    
                since_ts = float(since) if since else None
                messages = channel.get_messages(since_ts)
                
                return {
                    "messages": [
                        {
                            "id": msg.id,
                            "sender_id": msg.sender_id,
                            "content": msg.content,
                            "timestamp": msg.timestamp
                        }
                        for msg in messages
                    ]
                }, 200
            
            else:
                return {"error": "Invalid endpoint or method"}, 404
                
        except Exception as e:
            print(f"[HttpAdapter] Error handling chat endpoint: {str(e)}")
            return {"error": "Internal server error"}, 500

    def build_response(self, req, resp):
        """Builds a :class:`Response <Response>` object 

        :param req: The :class:`Request <Request>` used to generate the response.
        :param resp: The  response object.
        :rtype: Response
        """
        response = Response()
        response.raw = resp
        response.reason = response.raw.reason

        if isinstance(req.url, bytes):
            response.url = req.url.decode("utf-8")
        else:
            response.url = req.url

        # Give the Response some context.
        response.request = req
        response.connection = self

        return response

    # def get_connection(self, url, proxies=None):
        # """Returns a url connection for the given URL. 

        # :param url: The URL to connect to.
        # :param proxies: (optional) A Requests-style dictionary of proxies used on this request.
        # :rtype: int
        # """

        # proxy = select_proxy(url, proxies)

        # if proxy:
            # proxy = prepend_scheme_if_needed(proxy, "http")
            # proxy_url = parse_url(proxy)
            # if not proxy_url.host:
                # raise InvalidProxyURL(
                    # "Please check proxy URL. It is malformed "
                    # "and could be missing the host."
                # )
            # proxy_manager = self.proxy_manager_for(proxy)
            # conn = proxy_manager.connection_from_url(url)
        # else:
            # # Only scheme should be lower case
            # parsed = urlparse(url)
            # url = parsed.geturl()
            # conn = self.poolmanager.connection_from_url(url)

        # return conn


    def add_headers(self, request):
        """
        Add headers to the request.

        This method is intended to be overridden by subclasses to inject
        custom headers. It does nothing by default.

        
        :param request: :class:`Request <Request>` to add headers to.
        """
        pass

    def build_proxy_headers(self, proxy):
        """Returns a dictionary of the headers to add to any request sent
        through a proxy. 

        :class:`HttpAdapter <HttpAdapter>`.

        :param proxy: The url of the proxy being used for this request.
        :rtype: dict
        """
        headers = {}
        #
        # TODO: build your authentication here
        #       username, password =...
        # we provide dummy auth here
        #
        username, password = ("user1", "password")

        if username:
            headers["Proxy-Authorization"] = (username, password)

        return headers

    def _handle_login(self, req):
        """
        Handle login requests by authenticating credentials and creating a session.
        
        Args:
            req (Request): The HTTP request object containing login credentials
            
        Returns:
            None: Sends HTTP response directly through socket connection
            
        Raises:
            ValueError: If request body is malformed or missing required fields
            IOError: If there are issues reading the index page
            Exception: For other unexpected errors during login process
        """
        try:
            # Parse form data
            if not req.body:
                print("[HttpAdapter] Error: Empty login request body")
                return self.conn.sendall(ResponseBuilder.bad_request("Missing credentials"))
                
            body = req.body.strip()
            print("[HttpAdapter] Processing login request")
            
            # Parse manually for simple form data
            form_data = {}
            try:
                for pair in body.split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        form_data[key] = value
            except Exception as e:
                print(f"[HttpAdapter] Error parsing form data: {str(e)}")
                return self.conn.sendall(ResponseBuilder.bad_request("Invalid form data"))
                    
            username = form_data.get('username', '')
            password = form_data.get('password', '')
            
            if not username or not password:
                print("[HttpAdapter] Error: Missing username or password")
                return self.conn.sendall(ResponseBuilder.bad_request("Username and password are required"))
            
            # Authenticate
            result = self.auth_manager.authenticate(username, password)
            if not result:
                return self.conn.sendall(ResponseBuilder.unauthorized())
                
            session_id, session = result
            
            # Get user info
            user = self.auth_manager.get_user(username)
            if not user:
                print("[HttpAdapter] Error: User not found")
                return self.conn.sendall(ResponseBuilder.unauthorized())
            
            # Read index page
            try:
                with open('www/index.html', 'r') as f:
                    index_page = f.read()
            except IOError as e:
                print(f"[HttpAdapter] Error reading index page: {str(e)}")
                return self.conn.sendall(ResponseBuilder.server_error("Error loading page"))
                
            # Send success response with session cookie
            print(f"[HttpAdapter] Login successful for user: {username}")
            return self.conn.sendall(
                ResponseBuilder.with_session(index_page, session_id)
            )
            
        except ValueError as e:
            print(f"[HttpAdapter] Validation error: {str(e)}")
            return self.conn.sendall(ResponseBuilder.bad_request(str(e)))
        except IOError as e:
            print(f"[HttpAdapter] IO error: {str(e)}")
            return self.conn.sendall(ResponseBuilder.server_error("Server configuration error"))
        except Exception as e:
            print(f"[HttpAdapter] Unexpected error during login: {str(e)}")
            return self.conn.sendall(ResponseBuilder.server_error("Internal server error"))
            
    def _get_auth_cookie(self, req) -> Optional[str]:
        """Extract auth cookie from request"""
        cookies = {}
        cookie_header = req.headers.get('cookie', '')
        if cookie_header:
            for pair in cookie_header.split(';'):
                if '=' in pair:
                    key, value = pair.strip().split('=', 1)
                    cookies[key.strip()] = value.strip()
        
        print("[Cookie] Headers:", req.headers)
        print("[Cookie] All cookies:", cookies)
        auth_cookie = cookies.get('auth')
        print("[Cookie] Auth cookie:", auth_cookie)
        return auth_cookie