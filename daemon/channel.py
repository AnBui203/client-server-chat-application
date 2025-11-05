"""
Channel management module for chat application.
Handles message storage, member management and access control for chat channels.
"""

import time
from typing import Dict, List, Optional
from dataclasses import dataclass, field

@dataclass
class Message:
    """Represents a chat message"""
    id: str  # Unique message ID 
    channel_id: str  # Channel this message belongs to
    sender_id: str  # ID of the sending peer
    content: str  # Message content
    timestamp: float = field(default_factory=time.time)  # When the message was sent

@dataclass
class Channel:
    """Represents a chat channel"""
    id: str  # Unique channel ID
    name: str  # Display name
    created_by: str  # ID of peer who created the channel
    description: str = ""  # Optional channel description
    is_private: bool = False  # Whether this is a private channel
    allowed_members: List[str] = field(default_factory=list)  # List of allowed member IDs for private channels
    
    # Runtime state (not persisted)
    _members: Dict[str, dict] = field(default_factory=dict)  # Current members {peer_id: peer_info}
    _messages: List[Message] = field(default_factory=list)  # Channel message history
    
    def add_member(self, peer_id: str, peer_info: dict) -> bool:
        """
        Add a member to the channel
        
        :param peer_id: ID of the peer to add
        :param peer_info: Peer information dictionary
        :return: True if added successfully
        """
        if self.is_private and peer_id not in self.allowed_members:
            return False
            
        self._members[peer_id] = peer_info
        return True
        
    def remove_member(self, peer_id: str) -> bool:
        """
        Remove a member from the channel
        
        :param peer_id: ID of the peer to remove
        :return: True if removed successfully
        """
        if peer_id in self._members:
            del self._members[peer_id]
            return True
        return False
        
    def add_message(self, msg: Message) -> bool:
        """
        Add a message to the channel history
        
        :param msg: Message to add
        :return: True if added successfully
        """
        if msg.channel_id != self.id:
            return False
            
        if self.is_private and msg.sender_id not in self.allowed_members:
            return False
            
        self._messages.append(msg)
        return True
        
    def get_messages(self, since: Optional[float] = None) -> List[Message]:
        """
        Get channel messages, optionally filtered by timestamp
        
        :param since: If provided, only return messages after this timestamp
        :return: List of messages
        """
        if since is None:
            return self._messages[:]
            
        return [m for m in self._messages if m.timestamp > since]
        
    def get_members(self) -> Dict[str, dict]:
        """Get current channel members"""
        return self._members.copy()

class ChannelManager:
    """Manages all chat channels in the system"""
    
    def __init__(self):
        self.channels: Dict[str, Channel] = {}  # All channels by ID
        
    def create_channel(self, channel_id: str, name: str, created_by: str,
                      description: str = "", is_private: bool = False,
                      allowed_members: List[str] = None) -> Optional[Channel]:
        """
        Create a new channel
        
        :param channel_id: Unique channel ID
        :param name: Display name for the channel
        :param created_by: ID of the creating peer
        :param description: Optional channel description
        :param is_private: Whether this is a private channel
        :param allowed_members: List of allowed member IDs for private channels
        :return: Created channel or None if ID already exists
        """
        if channel_id in self.channels:
            return None
            
        channel = Channel(
            id=channel_id,
            name=name,
            created_by=created_by,
            description=description,
            is_private=is_private,
            allowed_members=allowed_members or []
        )
        
        self.channels[channel_id] = channel
        return channel
        
    def get_channel(self, channel_id: str) -> Optional[Channel]:
        """Get a channel by ID"""
        return self.channels.get(channel_id)
        
    def list_channels(self, for_peer_id: Optional[str] = None) -> List[Channel]:
        """
        List available channels, optionally filtered for a specific peer
        
        :param for_peer_id: If provided, only return channels this peer can join
        :return: List of channels
        """
        if for_peer_id is None:
            return list(self.channels.values())
            
        return [
            c for c in self.channels.values()
            if not c.is_private or for_peer_id in c.allowed_members
        ]
        
    def delete_channel(self, channel_id: str) -> bool:
        """Delete a channel by ID"""
        if channel_id in self.channels:
            del self.channels[channel_id]
            return True
        return False