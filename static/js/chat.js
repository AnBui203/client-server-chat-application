// State
let currentChannel = null;
let currentChannelName = '';
let lastMessageTime = 0;
let pollingInterval = null;
let currentUserId = null;

// Connect to server and start heartbeat
async function initChat() {
    console.log('[Chat] Initializing chat...');
    try {
        // Check if user is authenticated
        const authResponse = await fetch('/api/check-auth');
        const authData = await authResponse.json();
        
        console.log('[Chat] Auth response:', authData);
        
        if (!authData.authenticated) {
            console.log('[Chat] Not authenticated, redirecting to login');
            window.location.href = '/login.html';
            return;
        }
        
        currentUserId = authData.user_id;
        document.getElementById('current-user').textContent = authData.user_id;
        
        console.log('[Chat] User authenticated:', currentUserId);
        
        startHeartbeat();
        loadChannels();
    } catch (err) {
        console.error('[Chat] Failed to connect:', err);
        alert('Connection failed. Please try again.');
    }
}

// Poll for new messages
async function pollMessages() {
    if (!currentChannel) {
        console.log('[Chat] No current channel, skipping poll');
        return;
    }
    
    try {
        const url = `/channels/messages?channel_id=${currentChannel}&since=${lastMessageTime}`;
        console.log('[Chat] Polling messages:', url);
        
        const response = await fetch(url);
        
        if (!response.ok) {
            console.error('[Chat] Poll failed with status:', response.status);
            return;
        }
        
        const data = await response.json();
        
        console.log('[Chat] Poll response:', data);
        
        if (data.messages && data.messages.length > 0) {
            console.log(`[Chat] Received ${data.messages.length} new messages`);
            data.messages.forEach(msg => {
                displayMessage(msg);
                lastMessageTime = Math.max(lastMessageTime, msg.timestamp);
            });
        } else {
            console.log('[Chat] No new messages');
        }
    } catch (err) {
        console.error('[Chat] Failed to poll messages:', err);
    }
}

// Load available channels
async function loadChannels() {
    try {
        const response = await fetch('/channels');
        const data = await response.json();
        
        const channelList = document.getElementById('channel-list');
        if (data.channels && data.channels.length > 0) {
            channelList.innerHTML = data.channels.map(ch => `
                <li onclick="joinChannel('${ch.id}', '${ch.name}')" class="channel-item">
                    <strong>${ch.name}</strong>
                    <span class="member-count">${ch.memberCount || 0} members</span>
                </li>
            `).join('');
        } else {
            channelList.innerHTML = '<li>No channels available</li>';
        }
    } catch (err) {
        console.error('Failed to load channels:', err);
    }
}

// Join a channel
async function joinChannel(channelId, channelName) {
    try {
        const response = await fetch('/channels/join', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                channelId: channelId,
                userId: currentUserId
            })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            // Stop previous polling
            if (pollingInterval) {
                clearInterval(pollingInterval);
            }
            
            currentChannel = channelId;
            currentChannelName = channelName;
            lastMessageTime = 0;
            
            // Update UI
            document.getElementById('current-channel').textContent = channelName;
            document.getElementById('messages').innerHTML = '';
            document.getElementById('message-input').disabled = false;
            document.getElementById('send-btn').disabled = false;
            
            // Start polling for this channel
            pollingInterval = setInterval(pollMessages, 1000);
            
            // Load existing messages
            pollMessages();
        } else {
            alert(`Failed to join channel: ${result.error || 'Unknown error'}`);
        }
    } catch (err) {
        console.error('Failed to join channel:', err);
        alert('Failed to join channel. Please try again.');
    }
}

// Send a message
async function sendMessage() {
    const input = document.getElementById('message-input');
    const message = input.value.trim();
    if (!message || !currentChannel) {
        console.log('[Chat] Cannot send: no message or no channel');
        return;
    }
    
    console.log('[Chat] Sending message:', message, 'to channel:', currentChannel);
    
    try {
        const response = await fetch('/channels/messages', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                channelId: currentChannel,
                message: message
            })
        });
        
        const result = await response.json();
        console.log('[Chat] Send response:', result);
        
        if (response.ok) {
            input.value = '';
            console.log('[Chat] Message sent successfully');
            // Message will appear via polling
        } else {
            console.error('[Chat] Failed to send:', result);
            alert(`Failed to send message: ${result.error || 'Unknown error'}`);
        }
    } catch (err) {
        console.error('[Chat] Send error:', err);
        alert('Failed to send message. Please try again.');
    }
}

// Handle Enter key in message input
function handleKeyPress(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendMessage();
    }
}

// Display a message
function displayMessage(msg) {
    console.log('[Chat] Displaying message:', msg);
    
    const messages = document.getElementById('messages');
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message';
    
    // Check if this is from current user
    if (msg.sender_id === currentUserId) {
        messageDiv.classList.add('own-message');
        console.log('[Chat] Own message');
    }
    
    const senderSpan = document.createElement('span');
    senderSpan.className = 'sender';
    senderSpan.textContent = msg.sender_name || msg.sender_id;
    
    const timeSpan = document.createElement('span');
    timeSpan.className = 'time';
    timeSpan.textContent = new Date(msg.timestamp * 1000).toLocaleTimeString();
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'content';
    contentDiv.textContent = msg.content;
    
    messageDiv.appendChild(senderSpan);
    messageDiv.appendChild(timeSpan);
    messageDiv.appendChild(contentDiv);
    
    messages.appendChild(messageDiv);
    messages.scrollTop = messages.scrollHeight;
    
    console.log('[Chat] Message displayed');
}

// Escape HTML to prevent XSS
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// Create a new channel
async function createChannel() {
    const name = prompt('Enter channel name:');
    if (!name || !name.trim()) return;
    
    const description = prompt('Enter channel description (optional):');
    
    try {
        const response = await fetch('/channels/create', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                name: name.trim(),
                description: description || '',
                isPrivate: false
            })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            alert('Channel created successfully!');
            loadChannels();
        } else {
            alert(`Failed to create channel: ${result.error || 'Unknown error'}`);
        }
    } catch (err) {
        console.error('Failed to create channel:', err);
        alert('Failed to create channel. Please try again.');
    }
}

// Logout
async function logout() {
    try {
        await fetch('/logout', {method: 'POST'});
        window.location.href = '/login.html';
    } catch (err) {
        console.error('Logout failed:', err);
    }
}

// Start heartbeat
function startHeartbeat() {
    setInterval(() => {
        fetch('/heartbeat', {method: 'POST'})
            .catch(err => console.error('Heartbeat failed:', err));
    }, 30000); // Every 30 seconds
}

// Initialize on load
window.onload = initChat;