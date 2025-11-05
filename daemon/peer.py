import json
import socket
import threading
import time
import uuid
import queue
from typing import Dict, List, Optional, Tuple
from .channel import Channel, Message, ChannelManager

class Peer:
    """
    Peer class implementing a hybrid client-server and P2P chat client.
    Connects to central tracker and maintains P2P connections with other peers.
    """
    
    def __init__(self, tracker_host: str, tracker_port: int, listen_port: int = 0, 
                 display_name: str = None):
        """
        Initialize a new peer
        
        :param tracker_host: Host of the central tracker server
        :param tracker_port: Port of the tracker server
        :param listen_port: Port to listen for P2P connections (0 = random port)
        :param display_name: Human-readable name for this peer
        """
        self.tracker_host = tracker_host
        self.tracker_port = tracker_port
        
        # Generate unique peer ID
        self.peer_id = str(uuid.uuid4())
        self.display_name = display_name or f"Peer-{self.peer_id[:8]}"
        
        # Start P2P server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('0.0.0.0', listen_port))
        self.listen_port = self.server_socket.getsockname()[1]  # Get actual port
        
        # Active P2P connections
        self.peers: Dict[str, socket.socket] = {}
        self.peer_lock = threading.Lock()
        
        # Message queues
        self.incoming_msgs = queue.Queue()  # All messages
        self.channel_msgs = queue.Queue()  # Channel-specific messages
        self.notifications = queue.Queue()  # System notifications
        
        # Channel management
        self.channels = ChannelManager()
        self.joined_channels: Dict[str, Channel] = {}  # Channels this peer has joined

        # Heartbeat failure tracking
        self.heartbeat_failures = 0
        self.max_heartbeat_failures = 3  # Max consecutive failures before stopping
        
        # Start listener thread
        self.running = True
        self.listener_thread = threading.Thread(target=self._listen_for_peers)
        self.listener_thread.daemon = True
        self.listener_thread.start()
        
        # Start heartbeat thread
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop)
        self.heartbeat_thread.daemon = True
        self.heartbeat_thread.start()

    def register_with_tracker(self) -> bool:
        """
        Register this peer with the central tracker
        
        :return: True if registration successful, False otherwise
        """
        try:
            # Determine local IP. For local testing (tracker on localhost) use 127.0.0.1
            if self.tracker_host in ("127.0.0.1", "localhost"):
                local_ip = "127.0.0.1"
            else:
                # In real deployment, use STUN or external discovery
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
            
            data = {
                "id": self.peer_id,
                "ip": local_ip,
                "port": self.listen_port,
                "meta": {"name": f"Peer-{self.peer_id[:8]}"}
            }
            
            # Send registration request
            response = self._tracker_request("POST", "/register", data)
            print(f"[Peer] Tracker response to register: {response}")
            if response.get("status") == "ok":
                print(f"[Peer] Registered with tracker as {self.peer_id}")
                return True
                
        except Exception as e:
            print(f"[Peer] Registration failed: {str(e)}")
        return False

    def get_active_peers(self) -> List[dict]:
        """Get list of active peers from tracker"""
        try:
            response = self._tracker_request(
                "GET", 
                "/peers",
                headers={"X-Exclude-Peer": self.peer_id}
            )
            print(f"[Peer] Tracker response to get /peers: {response}")
            return response.get("peers", [])
        except Exception as e:
            print(f"[Peer] Failed to get peer list: {str(e)}")
            return []

    def connect_to_peer(self, peer_info: dict) -> bool:
        """
        Establish P2P connection to another peer
        
        :param peer_info: Peer information from tracker
        :return: True if connection successful
        """
        peer_id = peer_info["id"]
        
        if peer_id in self.peers:
            return True  # Already connected
            
        try:
            # Create new connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_info["ip"], peer_info["port"]))
            
            # Send handshake
            handshake = {
                "type": "handshake",
                "peer_id": self.peer_id
            }
            sock.sendall(json.dumps(handshake).encode() + b'\n')
            
            # Add to active peers
            with self.peer_lock:
                self.peers[peer_id] = sock
                
            # Start message handler for this peer
            thread = threading.Thread(
                target=self._handle_peer_messages,
                args=(peer_id, sock)
            )
            thread.daemon = True
            thread.start()
            
            print(f"[Peer] Connected to peer {peer_id}")
            return True
            
        except Exception as e:
            print(f"[Peer] Failed to connect to {peer_id}: {str(e)}")
            return False

    def send_direct_message(self, peer_id: str, message: str):
        """Send direct message to specific peer"""
        if peer_id not in self.peers:
            print(f"[Peer] Not connected to peer {peer_id}")
            return False
            
        try:
            msg = {
                "type": "chat",
                "from": self.peer_id,
                "to": peer_id,
                "message": message
            }
            self.peers[peer_id].sendall(json.dumps(msg).encode() + b'\n')
            return True
        except Exception as e:
            print(f"[Peer] Failed to send message to {peer_id}: {str(e)}")
            self._remove_peer(peer_id)
            return False

    def broadcast_message(self, message: str):
        """Send message to all connected peers"""
        with self.peer_lock:
            peer_ids = list(self.peers.keys())
            
        for peer_id in peer_ids:
            self.send_direct_message(peer_id, message)

    def get_next_message(self, timeout: float = 0.1, message_type: str = "all") -> Optional[dict]:
        """
        Get next message from specified queue
        
        :param timeout: How long to wait for message
        :param message_type: Type of messages to retrieve ("all", "channel", or "notification")
        :return: Message dict or None if queue empty
        """
        try:
            if message_type == "channel":
                return self.channel_msgs.get(timeout=timeout)
            elif message_type == "notification":
                return self.notifications.get(timeout=timeout)
            else:
                return self.incoming_msgs.get(timeout=timeout)
        except queue.Empty:
            return None

    def create_channel(self, name: str, description: str = "", 
                      is_private: bool = False, allowed_members: List[str] = None) -> Optional[Channel]:
        """
        Create a new chat channel
        
        :param name: Display name for the channel
        :param description: Optional channel description 
        :param is_private: Whether this is a private channel
        :param allowed_members: List of allowed member IDs for private channels
        :return: Created channel or None if failed
        """
        channel_id = str(uuid.uuid4())
        
        try:
            # Create channel locally
            channel = self.channels.create_channel(
                channel_id=channel_id,
                name=name,
                created_by=self.peer_id,
                description=description,
                is_private=is_private,
                allowed_members=allowed_members
            )
            
            if not channel:
                return None
                
            # Register with tracker
            response = self._tracker_request(
                "POST",
                "/channels/create",
                {
                    "id": channel_id,
                    "name": name,
                    "created_by": self.peer_id,
                    "description": description,
                    "is_private": is_private,
                    "allowed_members": allowed_members or []
                }
            )
            
            if response.get("status") == "ok":
                # Auto-join own channel
                self.join_channel(channel_id)
                return channel
                
            # If tracker registration failed, delete local channel
            self.channels.delete_channel(channel_id)
            return None
            
        except Exception as e:
            print(f"[Peer] Failed to create channel: {str(e)}")
            return None

    def join_channel(self, channel_id: str) -> bool:
        """
        Join a chat channel
        
        :param channel_id: ID of channel to join
        :return: True if joined successfully
        """
        try:
            # Get channel info from tracker
            response = self._tracker_request(
                "POST",
                "/channels/join",
                {"channel_id": channel_id, "peer_id": self.peer_id}
            )
            
            if response.get("status") != "ok":
                return False
                
            channel = self.channels.get_channel(channel_id)
            if not channel:
                # Create local channel object from tracker data
                channel = self.channels.create_channel(
                    channel_id=response["channel"]["id"],
                    name=response["channel"]["name"],
                    created_by=response["channel"]["created_by"],
                    description=response["channel"].get("description", ""),
                    is_private=response["channel"].get("is_private", False),
                    allowed_members=response["channel"].get("allowed_members", [])
                )
                
            if not channel:
                return False
                
            # Add self as member
            if channel.add_member(self.peer_id, {
                "id": self.peer_id,
                "name": self.display_name
            }):
                self.joined_channels[channel_id] = channel
                # Notify UI
                self.notifications.put({
                    "type": "channel_joined",
                    "channel_id": channel_id,
                    "channel_name": channel.name
                })
                return True
                
            return False
            
        except Exception as e:
            print(f"[Peer] Failed to join channel {channel_id}: {str(e)}")
            return False

    def leave_channel(self, channel_id: str) -> bool:
        """
        Leave a chat channel
        
        :param channel_id: ID of channel to leave
        :return: True if left successfully
        """
        if channel_id not in self.joined_channels:
            return False
            
        try:
            # Notify tracker
            response = self._tracker_request(
                "POST", 
                "/channels/leave",
                {"channel_id": channel_id, "peer_id": self.peer_id}
            )
            
            if response.get("status") != "ok":
                return False
                
            # Remove from local state
            channel = self.joined_channels.pop(channel_id)
            channel.remove_member(self.peer_id)
            
            # Notify UI
            self.notifications.put({
                "type": "channel_left",
                "channel_id": channel_id,
                "channel_name": channel.name
            })
            
            return True
            
        except Exception as e:
            print(f"[Peer] Failed to leave channel {channel_id}: {str(e)}")
            return False

    def send_channel_message(self, channel_id: str, content: str) -> bool:
        """
        Send a message to a channel
        
        :param channel_id: ID of channel to send to
        :param content: Message content
        :return: True if sent successfully
        """
        if channel_id not in self.joined_channels:
            return False
            
        try:
            msg = Message(
                id=str(uuid.uuid4()),
                channel_id=channel_id,
                sender_id=self.peer_id,
                content=content
            )
            
            # Add to local channel
            channel = self.joined_channels[channel_id]
            if not channel.add_message(msg):
                return False
                
            # Broadcast to channel members
            message = {
                "type": "channel_message",
                "message": {
                    "id": msg.id,
                    "channel_id": msg.channel_id,
                    "sender_id": msg.sender_id,
                    "sender_name": self.display_name,
                    "content": msg.content,
                    "timestamp": msg.timestamp
                }
            }
            
            for member_id in channel.get_members():
                if member_id != self.peer_id:
                    self.send_direct_message(member_id, json.dumps(message))
                    
            return True
            
        except Exception as e:
            print(f"[Peer] Failed to send channel message: {str(e)}")
            return False

    def list_channels(self) -> List[Tuple[str, str, int]]:
        """
        Get list of available channels
        
        :return: List of (channel_id, name, member_count) tuples
        """
        try:
            response = self._tracker_request("GET", "/channels")
            channels = response.get("channels", [])
            
            # Update local channel list
            for ch in channels:
                if ch["id"] not in self.channels.channels:
                    self.channels.create_channel(
                        channel_id=ch["id"],
                        name=ch["name"],
                        created_by=ch["created_by"],
                        description=ch.get("description", ""),
                        is_private=ch.get("is_private", False),
                        allowed_members=ch.get("allowed_members", [])
                    )
                    
            return [
                (ch["id"], ch["name"], len(ch["members"]))
                for ch in channels
            ]
            
        except Exception as e:
            print(f"[Peer] Failed to list channels: {str(e)}")
            return []

    def get_channel_messages(self, channel_id: str, 
                           since: Optional[float] = None) -> List[Message]:
        """
        Get messages from a channel
        
        :param channel_id: Channel to get messages from
        :param since: Optional timestamp to filter messages
        :return: List of messages
        """
        if channel_id not in self.joined_channels:
            return []
            
        return self.joined_channels[channel_id].get_messages(since)

    def stop(self):
        """Stop peer and close all connections"""
        self.running = False
        
        # Deregister from tracker
        try:
            self._tracker_request("POST", "/deregister", {"id": self.peer_id})
        except:
            pass
            
        # Close all connections
        with self.peer_lock:
            for sock in self.peers.values():
                try:
                    sock.close()
                except:
                    pass
            self.peers.clear()
            
        # Close server socket
        try:
            self.server_socket.close()
        except:
            pass

    def _tracker_request(self, method: str, path: str, data: dict = None, headers: dict = None) -> dict:
        """Helper for making requests to tracker"""
        # Implement retry and timeout for tracker requests
        attempts = 3
        timeout = 3.0  # seconds per attempt
        last_err = None

        for attempt in range(1, attempts + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.connect((self.tracker_host, self.tracker_port))

                # Construct request with proper CRLF line endings
                request = f"{method} {path} HTTP/1.1\r\n"
                request += f"Host: {self.tracker_host}:{self.tracker_port}\r\n"
                request += "Content-Type: application/json\r\n"

                if headers:
                    for k, v in headers.items():
                        request += f"{k}: {v}\r\n"

                if data:
                    body = json.dumps(data)
                    request += f"Content-Length: {len(body)}\r\n"
                    request += "\r\n"
                    request += body
                else:
                    request += "\r\n"

                sock.sendall(request.encode())

                # Read response (may be larger; read until socket closes or timeout)
                response_parts = []
                while True:
                    try:
                        chunk = sock.recv(4096)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    response_parts.append(chunk)

                response = b"".join(response_parts).decode(errors='ignore')

                # Parse JSON response
                parts = response.split("\r\n\r\n", 1)
                if len(parts) == 2:
                    body = parts[1]
                else:
                    idx = response.find('{')
                    body = response[idx:] if idx != -1 else '{}'

                try:
                    return json.loads(body)
                except Exception as e:
                    raise RuntimeError(f"Invalid JSON response from tracker: {e} | raw:{body}")

            except Exception as e:
                last_err = e
                # clear socket and retry
                try:
                    sock.close()
                except:
                    pass
                if attempt < attempts:
                    time.sleep(0.5)
                    continue
                # if last attempt, raise a clear error
                raise RuntimeError(f"Tracker request failed after {attempts} attempts: {e}")
            finally:
                try:
                    sock.close()
                except:
                    pass

    def _listen_for_peers(self):
        """Listen for incoming P2P connections"""
        self.server_socket.listen(5)
        
        while self.running:
            try:
                sock, addr = self.server_socket.accept()
                
                # Handle handshake in separate thread
                thread = threading.Thread(
                    target=self._handle_new_peer,
                    args=(sock, addr)
                )
                thread.daemon = True
                thread.start()
                
            except Exception as e:
                if self.running:
                    print(f"[Peer] Listener error: {str(e)}")

    def _handle_new_peer(self, sock: socket.socket, addr):
        """Handle new incoming peer connection"""
        try:
            # Read handshake
            data = sock.recv(1024).decode()
            handshake = json.loads(data)
            
            if handshake["type"] != "handshake":
                raise ValueError("Invalid handshake")
                
            peer_id = handshake["peer_id"]
            
            # Add to active peers
            with self.peer_lock:
                self.peers[peer_id] = sock
                
            # Start message handler
            self._handle_peer_messages(peer_id, sock)
            
        except Exception as e:
            print(f"[Peer] Failed to handle new peer: {str(e)}")
            sock.close()

    def _handle_peer_messages(self, peer_id: str, sock: socket.socket):
        """Handle messages from a specific peer"""
        try:
            # Create buffer for incomplete messages
            buffer = ""
            
            while self.running:
                data = sock.recv(1024).decode()
                if not data:
                    break
                    
                buffer += data
                
                # Process complete messages
                while '\\n' in buffer:
                    message, buffer = buffer.split('\\n', 1)
                    try:
                        msg = json.loads(message)
                        self.incoming_msgs.put(msg)
                    except:
                        print(f"[Peer] Invalid message from {peer_id}")
                        
        except Exception as e:
            print(f"[Peer] Lost connection to {peer_id}: {str(e)}")
        
        self._remove_peer(peer_id)

    def _remove_peer(self, peer_id: str):
        """Remove a peer from active connections"""
        with self.peer_lock:
            if peer_id in self.peers:
                try:
                    self.peers[peer_id].close()
                except:
                    pass
                del self.peers[peer_id]

    def _heartbeat_loop(self):
        """Send periodic heartbeats to tracker"""
        while self.running:
            try:
                self._tracker_request(
                    "POST",
                    "/heartbeat",
                    {"id": self.peer_id}
                )
                # Reset failure counter on successful heartbeat
                self.heartbeat_failures = 0
            except Exception as e:
                print(f"[Peer] Heartbeat failed: {str(e)}")
                # Increment failure counter
                self.heartbeat_failures += 1
                print(f"[Peer] Consecutive heartbeat failures: {self.heartbeat_failures}")

                # Check if we've exceeded max failures
                if self.heartbeat_failures >= self.max_heartbeat_failures:
                    print(f"[Peer] Too many heartbeat failures ({self.heartbeat_failures}). Stopping peer.")
                    self.stop()
                    break
                
            # Wait for next heartbeat if still running
            if self.running:
                time.sleep(30)  # Heartbeat every 30 seconds