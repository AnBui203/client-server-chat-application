// State
let currentChannel = null;
let lastMessageTime = 0;

// Connect to server and start heartbeat
async function initChat() {
    try {
        const response = await fetch('/api/connect');
        const data = await response.json();
        if (data.success) {
            startHeartbeat();
            loadChannels();
        }
    } catch (err) {
        console.error('Failed to connect:', err);
        alert('Connection failed. Please try again.');
    }
}

// Poll for new messages
async function pollMessages() {
    if (!currentChannel) return;
    
    try {
        const response = await fetch(`/channels/messages?channel_id=${currentChannel}&since=${lastMessageTime}`);
        const data = await response.json();
        
        data.messages.forEach(msg => {
            displayMessage(msg);
            lastMessageTime = Math.max(lastMessageTime, msg.timestamp);
        });
    } catch (err) {
        console.error('Failed to poll messages:', err);
    }
}

// Load available channels
async function loadChannels() {
    try {
        const response = await fetch('/channels');
        const data = await response.json();
        
        const channelList = document.getElementById('channel-list');
        channelList.innerHTML = data.channels.map(ch => `
            <li onclick="joinChannel('${ch.id}')">${ch.name} (${ch.member_count})</li>
        `).join('');
    } catch (err) {
        console.error('Failed to load channels:', err);
    }
}

// Join a channel
async function joinChannel(channelId) {
    try {
        const response = await fetch('/channels/join', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({channel_id: channelId})
        });
        
        if (response.ok) {
            currentChannel = channelId;
            lastMessageTime = 0;
            document.getElementById('messages').innerHTML = '';
            pollMessages();
        }
    } catch (err) {
        console.error('Failed to join channel:', err);
    }
}

// Send a message
async function sendMessage() {
    const input = document.getElementById('message-input');
    const message = input.value.trim();
    if (!message || !currentChannel) return;
    
    try {
        await fetch('/channels/messages', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                channel_id: currentChannel,
                message: message
            })
        });
        input.value = '';
    } catch (err) {
        console.error('Failed to send message:', err);
        alert('Failed to send message. Please try again.');
    }
}

// Display a message
function displayMessage(msg) {
    const messages = document.getElementById('messages');
    messages.innerHTML += `
        <div class="message">
            <span class="sender">${msg.sender_name}</span>
            <span class="time">${new Date(msg.timestamp * 1000).toLocaleTimeString()}</span>
            <div class="content">${escapeHtml(msg.content)}</div>
        </div>
    `;
    messages.scrollTop = messages.scrollHeight;
}

// Escape HTML to prevent XSS
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// Start message polling and heartbeat
function startHeartbeat() {
    setInterval(() => {
        fetch('/heartbeat', {method: 'POST'});
    }, 30000);
    
    setInterval(pollMessages, 1000);
}

// Initialize on load
window.onload = initChat;