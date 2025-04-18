document.addEventListener('DOMContentLoaded', function() {
    const messageForm = document.getElementById('messageForm');
    const messageInput = document.getElementById('messageInput');
    const messageContainer = document.getElementById('messageContainer');
    const chatList = document.getElementById('chatList');
    const userList = document.getElementById('userList');
    const userSearchInput = document.getElementById('userSearchInput');
    const activeChatId = document.getElementById('activeChatId');
    const chatTitle = document.getElementById('chatTitle');
    const currentUsername = document.getElementById('currentUsername');
    const newChatModal = new bootstrap.Modal(document.getElementById('newChatModal'));

    // Initialize
    let lastMessageCount = 0;
    let activeChat = activeChatId.value;
    let lastMessageId = 0;
    let windowHasFocus = true;
    let notificationsEnabled = false;
    
    // Initialize notifications
    initNotifications();
    
    fetchMessages();
    loadChatRooms();
    const messagePollingInterval = setInterval(fetchMessages, 3000);
    const chatPollingInterval = setInterval(loadChatRooms, 10000);
    
    // Check if window has focus
    window.addEventListener('focus', function() {
        windowHasFocus = true;
    });
    
    window.addEventListener('blur', function() {
        windowHasFocus = false;
    });
    
    // Initialize browser notifications
    function initNotifications() {
        // Check if the browser supports notifications
        if (!('Notification' in window)) {
            console.log('This browser does not support notifications');
            return;
        }
        
        // Check if permission is already granted
        if (Notification.permission === 'granted') {
            notificationsEnabled = true;
        } else if (Notification.permission !== 'denied') {
            // Add a button to request notification permission
            const notifyBtn = document.createElement('button');
            notifyBtn.className = 'btn btn-sm btn-outline-secondary me-2';
            notifyBtn.innerHTML = '<i class="bi bi-bell"></i> Enable Notifications';
            notifyBtn.addEventListener('click', requestNotificationPermission);
            
            // Add the button to the header
            const headerBtns = document.querySelector('.card-header .d-flex.gap-2');
            headerBtns.prepend(notifyBtn);
        }
    }
    
    // Request notification permission
    function requestNotificationPermission() {
        Notification.requestPermission().then(function(permission) {
            if (permission === 'granted') {
                notificationsEnabled = true;
                // Remove the notification button after permission is granted
                const notifyBtn = document.querySelector('.btn-outline-secondary');
                if (notifyBtn) {
                    notifyBtn.remove();
                }
                // Show a success notification
                showNotification('Chat Notifications', 'Notifications are now enabled!');
            }
        });
    }
    
    // Show a notification
    function showNotification(title, body) {
        if (notificationsEnabled && !windowHasFocus) {
            const notification = new Notification(title, {
                body: body,
                icon: '/static/favicon.ico' // You may want to add a favicon to your static folder
            });
            
            // Close the notification after 5 seconds
            setTimeout(function() {
                notification.close();
            }, 5000);
            
            // Focus the window when the notification is clicked
            notification.onclick = function() {
                window.focus();
                this.close();
            };
        }
    }
    
    // Chat list item click
    chatList.addEventListener('click', function(e) {
        const chatItem = e.target.closest('.list-group-item');
        if (chatItem) {
            const chatId = chatItem.dataset.chatId;
            if (chatId !== activeChat) {
                activeChat = chatId;
                activeChatId.value = chatId;
                
                // Update UI
                document.querySelectorAll('#chatList .list-group-item').forEach(item => {
                    item.classList.remove('active');
                });
                chatItem.classList.add('active');
                
                // Update chat title
                chatTitle.textContent = chatItem.querySelector('.fw-bold').textContent;
                
                // Fetch messages for selected chat
                fetchMessages();
                
                // Update URL without page reload
                const url = chatId ? `/chat/${chatId}` : '/';
                history.pushState({}, '', url);
            }
        }
    });

    // Message form submission
    messageForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const message = messageInput.value.trim();
        if (!message) return;

        try {
            const formData = new FormData();
            formData.append('message', message);
            if (activeChat) {
                formData.append('chat_id', activeChat);
            }

            const response = await fetch('/send', {
                method: 'POST',
                body: formData
            });

            if (response.ok) {
                messageInput.value = '';
                await fetchMessages();
            } else {
                const data = await response.json();
                
                // Check if this is a blacklisted word error
                if (data.blacklisted_words && data.blacklisted_words.length > 0) {
                    // Create a nicer error message with the blacklisted words
                    const blockedWords = data.blacklisted_words.join('", "');
                    const errorMessage = `Your message contains inappropriate language: "${blockedWords}"`;
                    
                    // Add a message div to inform the user (will disappear after 5 seconds)
                    const errorDiv = document.createElement('div');
                    errorDiv.className = 'alert alert-danger mt-2 mb-2';
                    errorDiv.innerHTML = `<i class="bi bi-exclamation-triangle-fill"></i> ${errorMessage}`;
                    
                    // Insert before the message form
                    messageForm.parentNode.insertBefore(errorDiv, messageForm);
                    
                    // Remove after 5 seconds
                    setTimeout(() => {
                        errorDiv.remove();
                    }, 5000);
                } else {
                    // General error
                    alert(data.error || 'Failed to send message');
                }
            }
        } catch (error) {
            console.error('Error sending message:', error);
            alert('Failed to send message');
        }
    });

    // Load available users for new chat
    newChatModal._element.addEventListener('shown.bs.modal', loadUsers);

    // User search
    userSearchInput.addEventListener('input', function() {
        const searchTerm = this.value.toLowerCase();
        const userItems = userList.querySelectorAll('.list-group-item');
        
        userItems.forEach(item => {
            const username = item.textContent.toLowerCase();
            if (username.includes(searchTerm)) {
                item.style.display = 'block';
            } else {
                item.style.display = 'none';
            }
        });
    });

    // Start chat with selected user
    userList.addEventListener('click', async function(e) {
        const userItem = e.target.closest('.list-group-item');
        if (userItem) {
            const userId = userItem.dataset.userId;
            try {
                const formData = new FormData();
                formData.append('user_id', userId);
                
                const response = await fetch('/api/chats/create', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                if (response.ok) {
                    // Close modal
                    newChatModal.hide();
                    
                    // Load chat rooms and select the new one
                    await loadChatRooms();
                    
                    // Set the new chat as active
                    activeChat = data.chat.id;
                    activeChatId.value = activeChat;
                    
                    // Update URL without page reload
                    const url = `/chat/${activeChat}`;
                    history.pushState({}, '', url);
                    
                    // Update chat title
                    chatTitle.textContent = data.chat.name;
                    
                    // Fetch messages for selected chat
                    fetchMessages();
                } else {
                    alert(data.error || 'Failed to create chat');
                }
            } catch (error) {
                console.error('Error creating chat:', error);
                alert('Failed to create chat');
            }
        }
    });

    async function fetchMessages() {
        try {
            let url = '/messages';
            if (activeChat) {
                url += `?chat_id=${activeChat}`;
            }
            
            const response = await fetch(url);
            if (response.ok) {
                const messages = await response.json();
                
                // Check for new messages
                if (messages.length > 0) {
                    const latestMessageId = messages[messages.length - 1].id;
                    
                    // If we have new messages and this isn't the first load
                    if (lastMessageId > 0 && latestMessageId > lastMessageId && !windowHasFocus) {
                        // Find new messages
                        const newMessages = messages.filter(msg => msg.id > lastMessageId);
                        
                        // Show notifications for new messages
                        newMessages.forEach(msg => {
                            if (msg.username !== currentUsername.textContent) {
                                const chatName = chatTitle.textContent;
                                showNotification(
                                    `New message from ${msg.username}`,
                                    `${chatName}: ${msg.content}`
                                );
                            }
                        });
                    }
                    
                    // Update last message ID
                    lastMessageId = latestMessageId;
                }
                
                // Update UI if message count changed
                if (messages.length !== lastMessageCount) {
                    updateMessages(messages);
                    lastMessageCount = messages.length;
                }
            }
        } catch (error) {
            console.error('Error fetching messages:', error);
        }
    }

    async function loadChatRooms() {
        try {
            const response = await fetch('/api/chats');
            if (response.ok) {
                const chats = await response.json();
                
                // Update chat list but keep the global chat
                const globalChatItem = chatList.querySelector('[data-chat-id=""]');
                const activeChatItem = chatList.querySelector('.active');
                const activeChatIdValue = activeChatItem ? activeChatItem.dataset.chatId : '';
                
                // Keep only the global chat item
                chatList.innerHTML = '';
                chatList.appendChild(globalChatItem);
                
                // Add the chat rooms
                chats.forEach(chat => {
                    const otherUsers = chat.participants
                        .filter(p => p.username !== currentUsername.textContent)
                        .map(p => p.username)
                        .join(', ');
                    
                    const chatItem = document.createElement('li');
                    chatItem.className = `list-group-item d-flex justify-content-between align-items-center
                                        ${chat.id == activeChatIdValue ? 'active' : ''}`;
                    chatItem.dataset.chatId = chat.id;
                    chatItem.innerHTML = `
                        <div>
                            <div class="fw-bold">${chat.name}</div>
                            <small class="text-muted">${otherUsers}</small>
                        </div>
                    `;
                    chatList.appendChild(chatItem);
                });
            }
        } catch (error) {
            console.error('Error loading chat rooms:', error);
        }
    }

    async function loadUsers() {
        try {
            const response = await fetch('/api/users');
            if (response.ok) {
                const users = await response.json();
                
                if (users.length === 0) {
                    userList.innerHTML = `
                        <div class="text-center text-muted p-3">
                            <small>No online users available</small>
                        </div>
                    `;
                    return;
                }
                
                userList.innerHTML = '';
                users.forEach(user => {
                    const userItem = document.createElement('div');
                    userItem.className = 'list-group-item';
                    userItem.dataset.userId = user.id;
                    
                    const initial = user.username.charAt(0).toUpperCase();
                    userItem.innerHTML = `
                        <div class="user-item">
                            <div class="user-avatar">${initial}</div>
                            <div>${user.username}</div>
                            <div class="online-indicator"></div>
                        </div>
                    `;
                    userList.appendChild(userItem);
                });
            }
        } catch (error) {
            console.error('Error loading users:', error);
            userList.innerHTML = `
                <div class="text-center text-muted p-3">
                    <small>Failed to load users</small>
                </div>
            `;
        }
    }

    function updateMessages(messages) {
        const wasAtBottom = isAtBottom();
        messageContainer.innerHTML = '';

        if (messages.length === 0) {
            messageContainer.innerHTML = `
                <div class="text-center text-muted mb-3">
                    <small>No messages yet. Be the first to send a message!</small>
                </div>
            `;
            return;
        }

        messages.forEach(message => {
            const messageElement = createMessageElement(message);
            messageContainer.appendChild(messageElement);
        });

        if (wasAtBottom) {
            scrollToBottom();
        }
    }

    function createMessageElement(message) {
        const div = document.createElement('div');
        const isOwnMessage = message.username === currentUsername.textContent;
        div.className = `message ${isOwnMessage ? 'own' : 'other'}`;
        div.dataset.messageId = message.id;

        // Check if admin controls should be shown
        const isAdmin = document.body.dataset.isAdmin.toLowerCase() === 'true';
        const adminControls = isAdmin ? 
            `<div class="admin-controls">
                <button class="btn btn-sm btn-danger delete-message" 
                        onclick="deleteMessage(${message.id}, event)">
                    <i class="bi bi-trash"></i> Delete Message
                </button>
            </div>` : '';

        div.innerHTML = `
            <div class="message-bubble">
                ${!isOwnMessage ? `<div class="message-username">${message.username}</div>` : ''}
                ${message.content}
            </div>
            <div class="message-meta">
                <span class="message-author">${message.username}</span> • ${message.timestamp}
            </div>
            ${adminControls}
        `;

        return div;
    }

    function isAtBottom() {
        const threshold = 100;
        return (messageContainer.scrollHeight - messageContainer.scrollTop - messageContainer.clientHeight) < threshold;
    }

    function scrollToBottom() {
        messageContainer.scrollTop = messageContainer.scrollHeight;
    }

    // Set user as offline before closing tab
    window.addEventListener('beforeunload', function() {
        navigator.sendBeacon('/api/user/offline');
    });
});

// Admin function to delete messages
function deleteMessage(messageId, event) {
    if (!confirm('Are you sure you want to delete this message?')) {
        return;
    }
    
    event.preventDefault();
    
    fetch(`/admin/delete-message/${messageId}`, {
        method: 'POST',
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Remove the message element
            const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
            if (messageElement) {
                messageElement.remove();
            }
        } else {
            alert(data.error || 'Failed to delete message');
        }
    })
    .catch(error => {
        console.error('Error deleting message:', error);
        alert('Failed to delete message');
    });
}
