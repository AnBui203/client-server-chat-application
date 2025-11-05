# Authentication and Session Management Module
import base64
import hashlib
import json
import time
from typing import Dict, Optional, Tuple

class Session:
    """Represents a user session"""
    def __init__(self, user_id: str, expires: float):
        self.user_id = user_id
        self.expires = expires  # Timestamp when session expires
        self.data: Dict = {}  # Additional session data

    def is_expired(self) -> bool:
        """Check if session has expired"""
        return time.time() > self.expires

class AuthManager:
    """Manages authentication and sessions"""
    
    def __init__(self, session_timeout: int = 3600):
        """
        Initialize auth manager
        
        :param session_timeout: Session duration in seconds (default 1 hour)
        """
        self.users = {
            # Default admin user
            "admin": {
                "username": "admin",
                "password_hash": self._hash_password("password"),
                "display_name": "Administrator"
            },
            "user1": {
                "username": "user1",
                "password_hash": self._hash_password("user1pass"),
                "display_name": "User One"
            }
        }
        self.sessions: Dict[str, Session] = {}
        self.session_timeout = session_timeout

    def _hash_password(self, password: str) -> str:
        """Create salted hash of password"""
        salt = "WeApRous2025"  # In production, use per-user random salt
        salted = (password + salt).encode('utf-8')
        return hashlib.sha256(salted).hexdigest()

    def _create_session(self, username: str) -> Tuple[str, Session]:
        """
        Create new session for user
        
        :param username: Username to create session for
        :return: Tuple of (session_id, Session)
        """
        # Create random session ID
        session_id = base64.b64encode(hashlib.sha256(
            f"{username}:{time.time()}".encode()
        ).digest()).decode('utf-8')
        
        # Create session with expiry
        session = Session(
            user_id=username,
            expires=time.time() + self.session_timeout
        )
        
        self.sessions[session_id] = session
        return session_id, session

    def authenticate(self, username: str, password: str) -> Optional[Tuple[str, Session]]:
        """
        Authenticate user credentials
        
        :param username: Username to authenticate
        :param password: Password to verify
        :return: Tuple of (session_id, Session) if auth successful, None if failed
        """
        user = self.users.get(username)
        if not user:
            return None
            
        if self._hash_password(password) != user["password_hash"]:
            return None
            
        return self._create_session(username)

    def validate_session(self, session_id: str) -> Optional[Session]:
        """
        Validate a session ID
        
        :param session_id: Session ID to validate
        :return: Session if valid, None if invalid/expired
        """
        session = self.sessions.get(session_id)
        if not session:
            return None
            
        if session.is_expired():
            del self.sessions[session_id]
            return None
            
        return session

    def get_user(self, username: str) -> Optional[dict]:
        """Get user info by username"""
        return self.users.get(username)

    def logout(self, session_id: str):
        """Remove a session"""
        if session_id in self.sessions:
            del self.sessions[session_id]

    def cleanup_expired(self):
        """Remove all expired sessions"""
        now = time.time()
        expired = [
            sid for sid, session in self.sessions.items()
            if session.expires <= now
        ]
        for sid in expired:
            del self.sessions[sid]

class ResponseBuilder:
    """Helper for building HTTP responses"""
    
    @staticmethod
    def unauthorized(body: str = "401 Unauthorized") -> bytes:
        """Build 401 Unauthorized response"""
        response = [
            "HTTP/1.1 401 Unauthorized",
            "Content-Type: text/html",
            f"Content-Length: {len(body)}",
            "Set-Cookie: auth=false; Path=/",
            "",
            body
        ]
        return "\r\n".join(response).encode()

    @staticmethod
    def redirect(location: str) -> bytes:
        """Build 302 redirect response"""
        response = [
            "HTTP/1.1 302 Found",
            f"Location: {location}",
            "Content-Length: 0",
            "",
            ""
        ]
        return "\r\n".join(response).encode()

    @staticmethod
    def ok(body: str, content_type: str = "text/html") -> bytes:
        """Build 200 OK response"""
        response = [
            "HTTP/1.1 200 OK",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body)}",
            "",
            body
        ]
        return "\r\n".join(response).encode()

    @staticmethod
    def with_session(body: str, session_id: str,
                    content_type: str = "text/html") -> bytes:
        """Build 200 OK response with session cookie"""
        response = [
            "HTTP/1.1 200 OK", 
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body)}",
            f"Set-Cookie: auth={session_id}; Path=/; HttpOnly",
            "",
            body
        ]
        return "\r\n".join(response).encode()

    @staticmethod
    def redirect_with_logout(location: str) -> bytes:
        """Build 302 redirect response that also clears auth cookie"""
        # Expire the cookie in the past to force browser to remove it
        expire = "Thu, 01 Jan 1970 00:00:00 GMT"
        response = [
            "HTTP/1.1 302 Found",
            f"Location: {location}",
            f"Set-Cookie: auth=; Path=/; Expires={expire}; HttpOnly",
            "Content-Length: 0",
            "",
            ""
        ]
        return "\r\n".join(response).encode()