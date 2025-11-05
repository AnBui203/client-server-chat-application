import threading
import time
from typing import Dict, Any

class PeerTracker:
    """
    Thread-safe tracker for managing active peers in the chat system.
    Stores peer information with TTL and provides methods to register,
    deregister, and list active peers.
    """
    
    def __init__(self, ttl_seconds: int = 120):
        self.peers: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        self.ttl_seconds = ttl_seconds
    
    def register_peer(self, peer_id: str, ip: str, port: int, meta: dict = None) -> bool:
        """
        Register a new peer or update existing peer's information
        
        :param peer_id: Unique identifier for the peer
        :param ip: IP address of the peer
        :param port: Port number the peer is listening on
        :param meta: Optional metadata about the peer
        :return: True if registered successfully, False if invalid data
        """
        if not all([peer_id, ip, port]):
            return False
            
        with self.lock:
            self.peers[peer_id] = {
                "id": peer_id,
                "ip": ip,
                "port": port,
                "meta": meta or {},
                "last_seen": time.time()
            }
        print(f"[PeerTracker] Registered peer {peer_id} @ {ip}:{port}")
        return True
    
    def deregister_peer(self, peer_id: str) -> bool:
        """
        Remove a peer from the tracking list
        
        :param peer_id: ID of peer to remove
        :return: True if peer was found and removed, False otherwise
        """
        with self.lock:
            if peer_id in self.peers:
                del self.peers[peer_id]
                return True
            return False
    
    def get_peer(self, peer_id: str) -> dict:
        """
        Get information about a specific peer
        
        :param peer_id: ID of the peer to get information for
        :return: Dictionary containing peer information or None if not found
        """
        with self.lock:
            return self.peers.get(peer_id)
    
    def update_peer_timestamp(self, peer_id: str) -> bool:
        """
        Update last_seen timestamp for a peer (used for heartbeat)
        
        :param peer_id: ID of the peer
        :return: True if peer exists and was updated, False otherwise
        """
        with self.lock:
            if peer_id in self.peers:
                self.peers[peer_id]["last_seen"] = time.time()
                print(f"[PeerTracker] Updated timestamp for {peer_id}")
                return True
        return False
    
    def get_active_peers(self, exclude_peer: str = None) -> list:
        """
        Get list of currently active peers
        
        :param exclude_peer: Optional peer ID to exclude from results
        :return: List of active peer information dictionaries
        """
        now = time.time()
        active_peers = []
        
        with self.lock:
            for peer_id, peer_info in self.peers.items():
                # Skip if peer should be excluded
                if peer_id == exclude_peer:
                    continue
                    
                # Check if peer is still active (within TTL)
                if now - peer_info["last_seen"] <= self.ttl_seconds:
                    # Make a copy of peer info without internal last_seen
                    peer_data = {
                        "id": peer_info["id"],
                        "ip": peer_info["ip"],
                        "port": peer_info["port"],
                        "meta": peer_info["meta"]
                    }
                    active_peers.append(peer_data)
        print(f"[PeerTracker] Returning {len(active_peers)} active peers (exclude={exclude_peer})")
                
        return active_peers
    
    def cleanup_expired(self) -> int:
        """
        Remove peers that haven't been seen for longer than TTL
        
        :return: Number of peers removed
        """
        now = time.time()
        removed = 0
        
        with self.lock:
            expired = [
                peer_id for peer_id, info in self.peers.items()
                if now - info["last_seen"] > self.ttl_seconds
            ]
            for peer_id in expired:
                del self.peers[peer_id]
                removed += 1
                
        return removed