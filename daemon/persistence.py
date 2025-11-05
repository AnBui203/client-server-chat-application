"""
Persistence module for storing channel data and message history
"""

import json
import os
from typing import Dict, List, Optional
from .channel import Channel, Message, ChannelManager
import time

class DataPersistence:
    """Handles saving and loading channel data to/from disk"""
    
    def __init__(self, data_file: str = "chat_data.json"):
        """
        Initialize persistence manager
        
        :param data_file: Path to JSON file for storing data
        """
        self.data_file = data_file
        
    def save_channels(self, channel_manager: ChannelManager) -> bool:
        """
        Save all channels and their messages to disk
        
        :param channel_manager: ChannelManager instance to save
        :return: True if successful, False otherwise
        """
        try:
            data = {
                "channels": {},
                "last_saved": time.time()
            }
            
            for channel_id, channel in channel_manager.channels.items():
                data["channels"][channel_id] = {
                    "id": channel.id,
                    "name": channel.name,
                    "created_by": channel.created_by,
                    "description": channel.description,
                    "is_private": channel.is_private,
                    "allowed_members": channel.allowed_members,
                    "messages": [
                        {
                            "id": msg.id,
                            "channel_id": msg.channel_id,
                            "sender_id": msg.sender_id,
                            "content": msg.content,
                            "timestamp": msg.timestamp
                        }
                        for msg in channel._messages
                    ]
                }
            
            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            print(f"[Persistence] Saved {len(channel_manager.channels)} channels to {self.data_file}")
            return True
            
        except Exception as e:
            print(f"[Persistence] Error saving data: {str(e)}")
            return False
    
    def load_channels(self, channel_manager: ChannelManager) -> bool:
        """
        Load channels and messages from disk
        
        :param channel_manager: ChannelManager instance to load into
        :return: True if successful, False otherwise
        """
        if not os.path.exists(self.data_file):
            print(f"[Persistence] No data file found at {self.data_file}")
            return False
        
        try:
            with open(self.data_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for channel_id, channel_data in data["channels"].items():
                # Create channel
                channel = channel_manager.create_channel(
                    channel_id=channel_data["id"],
                    name=channel_data["name"],
                    created_by=channel_data["created_by"],
                    description=channel_data.get("description", ""),
                    is_private=channel_data.get("is_private", False),
                    allowed_members=channel_data.get("allowed_members", [])
                )
                
                if channel:
                    # Restore messages
                    for msg_data in channel_data.get("messages", []):
                        message = Message(
                            id=msg_data["id"],
                            channel_id=msg_data["channel_id"],
                            sender_id=msg_data["sender_id"],
                            content=msg_data["content"],
                            timestamp=msg_data["timestamp"]
                        )
                        channel._messages.append(message)
            
            print(f"[Persistence] Loaded {len(channel_manager.channels)} channels from {self.data_file}")
            return True
            
        except Exception as e:
            print(f"[Persistence] Error loading data: {str(e)}")
            return False
    
    def auto_save_on_message(self, channel_manager: ChannelManager):
        """
        Save data after each message (can be optimized later with batching)
        
        :param channel_manager: ChannelManager instance to save
        """
        self.save_channels(channel_manager)
