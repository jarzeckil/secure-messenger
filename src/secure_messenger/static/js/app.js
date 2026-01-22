/**
 * Secure Messenger - Frontend Application
 * Vanilla JavaScript with Fetch API for backend communication
 */

// ========================================
// UTILITY FUNCTIONS
// ========================================

/**
 * Display a toast notification
 * @param {string} message - The message to display
 * @param {string} type - Type of notification: 'success', 'error', 'warning', 'info'
 */
function showNotification(message, type = 'info') {
    const toast = document.getElementById('notification-toast');
    const toastTitle = document.getElementById('toast-title');
    const toastMessage = document.getElementById('toast-message');
    const toastIcon = document.getElementById('toast-icon');

    // Remove existing type classes
    toast.classList.remove('success', 'error', 'warning', 'info');
    toast.classList.add(type);

    // Set icon based on type
    const icons = {
        success: 'bi-check-circle-fill',
        error: 'bi-x-circle-fill',
        warning: 'bi-exclamation-triangle-fill',
        info: 'bi-info-circle-fill'
    };

    const titles = {
        success: 'Success',
        error: 'Error',
        warning: 'Warning',
        info: 'Info'
    };

    toastIcon.className = `${icons[type]} me-2`;
    toastTitle.innerText = titles[type];
    toastMessage.innerText = message;

    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
}

/**
 * Format a date string to a human-readable format
 * @param {string} isoDate - ISO date string
 * @returns {string} Formatted date
 */
function formatDate(isoDate) {
    const date = new Date(isoDate);
    const now = new Date();
    const diff = now - date;

    // Less than 1 minute
    if (diff < 60000) {
        return 'Just now';
    }

    // Less than 1 hour
    if (diff < 3600000) {
        const minutes = Math.floor(diff / 60000);
        return `${minutes} min${minutes > 1 ? 's' : ''} ago`;
    }

    // Less than 24 hours
    if (diff < 86400000) {
        const hours = Math.floor(diff / 3600000);
        return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    }

    // Less than 7 days
    if (diff < 604800000) {
        const days = Math.floor(diff / 86400000);
        return `${days} day${days > 1 ? 's' : ''} ago`;
    }

    // Format as date
    return date.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        year: date.getFullYear() !== now.getFullYear() ? 'numeric' : undefined
    });
}

/**
 * Format file size to human-readable format
 * @param {number} bytes - File size in bytes
 * @returns {string} Formatted file size
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

/**
 * Handle API errors transparently - always show backend error detail
 * @param {Response} response - Fetch API response
 * @param {Object} data - Response data (if already parsed)
 * @returns {boolean} - True if error was handled with redirect, false otherwise
 */
function handleAPIError(response, data) {
    const detail = data?.detail || 'An error occurred';

    // Handle 401 Unauthorized
    if (response.status === 401) {
        // Only redirect to login if session truly expired
        if (detail === 'Session expired' || detail === "Session doesn't exist" || detail === 'Not authenticated') {
            showNotification(detail, 'error');
            setTimeout(() => {
                window.location.href = '/auth';
            }, 2000);
            return true;
        }

        // Redirect to 2FA verification if needed (case-insensitive check)
        if (detail.toLowerCase() === '2fa verification required' || detail === '2FA verification required') {
            showNotification('Please complete 2FA verification', 'info');
            window.location.href = '/auth?view=2fa-verify';
            return true;
        }
    }

    // For ALL other errors, show the exact backend error detail
    showNotification(detail, 'error');
    return false;
}

// ========================================
// AUTHENTICATION MODULE
// ========================================

const authModule = {
    init() {
        this.bindEvents();
        this.checkInitialView();
    },

    checkInitialView() {
        // Check URL params for specific view
        const params = new URLSearchParams(window.location.search);
        const view = params.get('view');
        if (view === '2fa-verify') {
            this.showView('2fa-verify-view');
        }
    },

    bindEvents() {
        // Login form
        const loginForm = document.getElementById('login-form');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleLogin();
            });
        }

        // Register form
        const registerForm = document.getElementById('register-form');
        if (registerForm) {
            registerForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleRegister();
            });
        }

        // 2FA verify form
        const twoFAVerifyForm = document.getElementById('2fa-verify-form');
        if (twoFAVerifyForm) {
            twoFAVerifyForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handle2FAVerify();
            });
        }

        // 2FA setup form
        const twoFASetupForm = document.getElementById('2fa-setup-form');
        if (twoFASetupForm) {
            twoFASetupForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handle2FASetup();
            });
        }

        // 2FA setup confirm button
        const twoFAConfirmBtn = document.getElementById('2fa-setup-complete');
        if (twoFAConfirmBtn) {
            twoFAConfirmBtn.addEventListener('click', () => {
                this.handle2FAConfirm();
            });
        }

        // View switching
        document.getElementById('show-register')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.showView('register-view');
        });

        document.getElementById('show-login')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.showView('login-view');
        });

        // Logout from 2FA button
        const logoutFrom2FABtn = document.getElementById('logout-from-2fa');
        if (logoutFrom2FABtn) {
            logoutFrom2FABtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.handleLogoutFrom2FA();
            });
        }
    },

    showView(viewId) {
        const views = ['login-view', 'register-view', '2fa-verify-view', '2fa-setup-view'];
        views.forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.style.display = id === viewId ? 'block' : 'none';
            }
        });
    },

    async handleLogin() {
        const username = document.getElementById('login-username').value.trim();
        const password = document.getElementById('login-password').value;

        try {
            const response = await fetch('/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (!response.ok) {
                handleAPIError(response, data);
                return;
            }

            // Store username in localStorage for display
            localStorage.setItem('username', username);

            // Check if 2FA is required
            if (data.require_2fa) {
                showNotification('Please enter your 2FA code', 'info');
                this.showView('2fa-verify-view');
            } else {
                showNotification('Login successful!', 'success');
                setTimeout(() => {
                    window.location.href = '/inbox';
                }, 1000);
            }
        } catch (error) {
            console.error('Login error:', error);
            showNotification('Network error. Please try again.', 'error');
        }
    },

    async handleRegister() {
        const username = document.getElementById('register-username').value.trim();
        const password = document.getElementById('register-password').value;
        const confirmPassword = document.getElementById('register-password-confirm').value;

        // Validate passwords match
        if (password !== confirmPassword) {
            showNotification('Passwords do not match!', 'error');
            return;
        }

        try {
            const response = await fetch('/auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (!response.ok) {
                // Handle 400 errors (user already exists, already logged in, etc.)
                if (response.status === 400) {
                    handleAPIError(response, data);
                }
                // Handle validation errors (422) with array format
                else if (response.status === 422 && data.detail && Array.isArray(data.detail)) {
                    const errorMsg = data.detail[0].msg || data.detail[0].detail || 'Validation error';

                    // Parse password validation error to show it cleanly
                    const cleanError = this.parsePasswordError(errorMsg);
                    showNotification(cleanError, 'error');
                } else {
                    // For all other errors, show exact backend detail
                    handleAPIError(response, data);
                }
                return;
            }

            showNotification('Registration successful! Please login.', 'success');
            setTimeout(() => {
                this.showView('login-view');
                // Clear the register form
                document.getElementById('register-form').reset();
            }, 1500);
        } catch (error) {
            console.error('Registration error:', error);
            showNotification('Network error. Please try again.', 'error');
        }
    },

    parsePasswordError(errorMsg) {
        // Check if it's a password validation error
        if (!errorMsg.includes('Password score')) {
            return errorMsg;
        }

        try {
            // Extract the password score
            const scoreMatch = errorMsg.match(/Password score: (\d+)\/(\d+)/);
            const score = scoreMatch ? scoreMatch[1] : '?';
            const maxScore = scoreMatch ? scoreMatch[2] : '4';

            // Extract warning message (between "Warning!" and "Suggestions:")
            let warning = '';
            const warningMatch = errorMsg.match(/Warning!\s*([^.]+\.)/);
            if (warningMatch) {
                warning = warningMatch[1].trim();
            }

            // Extract suggestions (everything inside the square brackets)
            let suggestions = [];
            const suggestionsMatch = errorMsg.match(/Suggestions:\s*\[([^\]]+)\]/);
            if (suggestionsMatch) {
                // Parse the suggestions - they're quoted strings separated by commas
                const suggestionsText = suggestionsMatch[1];
                suggestions = suggestionsText
                    .split(',')
                    .map(s => s.trim().replace(/^['"]|['"]$/g, ''))
                    .filter(s => s.length > 0);
            }

            // Build a clean error message
            let cleanMessage = `Weak password (strength: ${score}/${maxScore}).`;

            if (warning) {
                cleanMessage += ` ${warning}`;
            }

            if (suggestions.length > 0) {
                cleanMessage += ` Suggestions: ${suggestions.join(' ')}`;
            }

            return cleanMessage;
        } catch (e) {
            // If parsing fails, return the original message
            console.error('Error parsing password validation message:', e);
            return errorMsg;
        }
    },

    async handle2FAVerify() {
        const code = document.getElementById('2fa-code').value.trim();

        try {
            const response = await fetch('/auth/2fa/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ code })
            });

            const data = await response.json();

            if (!response.ok) {
                handleAPIError(response, data);
                return;
            }

            showNotification('Verification successful!', 'success');
            setTimeout(() => {
                window.location.href = '/inbox';
            }, 1000);
        } catch (error) {
            console.error('2FA verification error:', error);
            showNotification('Network error. Please try again.', 'error');
        }
    },

    async handle2FASetup() {
        const password = document.getElementById('2fa-setup-password').value;

        try {
            const response = await fetch('/auth/2fa/setup', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password })
            });

            const data = await response.json();

            if (!response.ok) {
                handleAPIError(response, data);
                return;
            }

            // Display QR code and secret
            document.getElementById('2fa-setup-content').style.display = 'none';
            document.getElementById('2fa-qr-display').style.display = 'block';
            document.getElementById('qr-code-image').src = `data:image/png;base64,${data.qr}`;
            document.getElementById('totp-secret').innerText = data.totp_secret;

            // Show the confirmation input and button
            document.getElementById('2fa-confirm-section').style.display = 'block';
        } catch (error) {
            console.error('2FA setup error:', error);
            showNotification('Network error. Please try again.', 'error');
        }
    },

    async handle2FAConfirm() {
        const code = document.getElementById('2fa-confirm-code').value.trim();

        try {
            const response = await fetch('/auth/2fa/enable', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ code })
            });

            const data = await response.json();

            if (!response.ok) {
                handleAPIError(response, data);
                return;
            }

            showNotification('2FA enabled successfully!', 'success');
            setTimeout(() => {
                window.location.href = '/inbox';
            }, 1500);
        } catch (error) {
            console.error('2FA confirm error:', error);
            showNotification('Network error. Please try again.', 'error');
        }
    },

    async handleLogoutFrom2FA() {
        try {
            // Call the logout endpoint to clear session cookies
            const response = await fetch('/auth/logout', {
                method: 'POST',
                credentials: 'include'
            });

            if (response.ok) {
                const data = await response.json();
                showNotification(data.message || 'Logged out successfully', 'success');
            } else {
                showNotification('Logged out', 'info');
            }
        } catch (error) {
            console.error('Logout error:', error);
            showNotification('Logged out', 'info');
        } finally {
            // Always clear local data and return to login view
            localStorage.removeItem('username');

            // Clear the 2FA code input
            const codeInput = document.getElementById('2fa-code');
            if (codeInput) {
                codeInput.value = '';
            }

            // Return to login view
            setTimeout(() => {
                this.showView('login-view');
            }, 500);
        }
    }
};

// ========================================
// INBOX MODULE
// ========================================

const inboxModule = {
    currentPage: 1,
    messagesPerPage: 50,
    messages: [],
    selectedMessageId: null,

    init() {
        this.bindEvents();
        this.loadMessages();
        this.getCurrentUser();
    },

    bindEvents() {
        // Compose button and modal
        const composeBtn = document.getElementById('compose-btn');
        const composeModal = new bootstrap.Modal(document.getElementById('compose-modal'));

        if (composeBtn) {
            composeBtn.addEventListener('click', () => {
                composeModal.show();
            });
        }

        // Send message button
        document.getElementById('send-message-btn')?.addEventListener('click', () => {
            this.handleSendMessage();
        });

        // File input change
        document.getElementById('compose-files')?.addEventListener('change', (e) => {
            const fileCount = e.target.files.length;
            const fileCountSpan = document.getElementById('file-count');
            if (fileCount === 0) {
                fileCountSpan.innerText = 'No files selected';
            } else if (fileCount > 5) {
                fileCountSpan.innerText = 'Maximum 5 files allowed';
                fileCountSpan.style.color = 'var(--accent-red)';
            } else {
                fileCountSpan.innerText = `${fileCount} file${fileCount > 1 ? 's' : ''} selected`;
                fileCountSpan.style.color = 'var(--text-secondary)';
            }
        });

        // Message actions
        document.getElementById('delete-message-btn')?.addEventListener('click', () => {
            this.handleDeleteMessage();
        });

        document.getElementById('verify-signature-btn')?.addEventListener('click', () => {
            this.handleVerifySignature();
        });

        document.getElementById('reply-btn')?.addEventListener('click', () => {
            this.handleReply();
        });

        // Pagination
        document.getElementById('prev-page-btn')?.addEventListener('click', () => {
            if (this.currentPage > 1) {
                this.currentPage--;
                this.loadMessages();
            }
        });

        document.getElementById('next-page-btn')?.addEventListener('click', () => {
            this.currentPage++;
            this.loadMessages();
        });

        // Refresh messages
        document.getElementById('refresh-messages-btn')?.addEventListener('click', () => {
            this.loadMessages();
        });

        // Logout
        document.getElementById('logout-btn')?.addEventListener('click', () => {
            this.handleLogout();
        });

        // 2FA Setup from inbox
        document.getElementById('setup-2fa-btn')?.addEventListener('click', () => {
            this.show2FASetupModal();
        });

        // 2FA modal form
        document.getElementById('2fa-modal-setup-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handle2FASetupFromInbox();
        });

        document.getElementById('2fa-modal-complete-btn')?.addEventListener('click', () => {
            this.handle2FAConfirmFromInbox();
        });
    },

    async getCurrentUser() {
        const usernameSpan = document.getElementById('current-username');
        if (usernameSpan) {
            const username = localStorage.getItem('username') || 'User';
            usernameSpan.innerText = username;
        }
    },

    async loadMessages() {
        const skip = (this.currentPage - 1) * this.messagesPerPage;

        try {
            const response = await fetch(`/messages/get?skip=${skip}&limit=${this.messagesPerPage}`);

            if (!response.ok) {
                const data = await response.json();
                if (handleAPIError(response, data)) {
                    return;
                }
                throw new Error('Failed to load messages');
            }

            this.messages = await response.json();
            this.renderMessageList();
            this.updatePagination();
        } catch (error) {
            console.error('Error loading messages:', error);
            showNotification('Failed to load messages.', 'error');
        }
    },

    renderMessageList() {
        const messageList = document.getElementById('message-list');

        if (!messageList) return;

        if (this.messages.length === 0) {
            messageList.innerHTML = `
                <div class="text-center text-muted p-4">
                    <i class="bi bi-inbox" style="font-size: 3rem;"></i>
                    <p class="mt-3">No messages found</p>
                </div>
            `;
            return;
        }

        messageList.innerHTML = this.messages.map(msg => `
            <div class="message-item ${msg.is_read ? '' : 'unread'} ${this.selectedMessageId === msg.message_id ? 'selected' : ''}"
                 data-message-id="${msg.message_id}">
                <div class="message-item-header">
                    <div class="message-sender">
                        ${!msg.is_read ? '<span class="unread-indicator"></span><strong>[Unread]</strong> ' : ''}
                        <i class="bi bi-person-circle"></i>
                        ${this.escapeHtml(msg.sender_username)}
                    </div>
                    <div class="message-date">${formatDate(msg.timestamp)}</div>
                </div>
                <div class="message-preview">${this.escapeHtml(msg.text_content.substring(0, 100))}${msg.text_content.length > 100 ? '...' : ''}</div>
            </div>
        `).join('');

        // Add click handlers to message items
        messageList.querySelectorAll('.message-item').forEach(item => {
            item.addEventListener('click', () => {
                const messageId = item.getAttribute('data-message-id');
                this.selectMessage(messageId);
            });
        });
    },

    async selectMessage(messageId) {
        const message = this.messages.find(m => String(m.message_id) === String(messageId));

        if (!message) {
            console.error('Message not found inside local state for ID:', messageId);
            return;
        }

        this.selectedMessageId = messageId;

        // Display message details FIRST (before any async operations)
        this.displayMessageDetail(message);

        // Then update UI to show selected state
        this.renderMessageList();

        // Mark as read in the background (if unread)
        if (!message.is_read) {
            const success = await this.markAsRead(messageId);
            if (success) {
                message.is_read = true;
                // Re-render one more time to update read status
                this.renderMessageList();
            }
        }
    },

    displayMessageDetail(message) {
        const noMessageDiv = document.getElementById('no-message-selected');
        const messageDetailDiv = document.getElementById('message-detail');

        if (!noMessageDiv || !messageDetailDiv) return;

        // Hide "No Message Selected"
        noMessageDiv.classList.remove('d-flex');
        noMessageDiv.classList.add('d-none');

        // Show message details
        messageDetailDiv.style.display = 'block';

        // Set message details using innerText for XSS protection
        const senderEl = document.getElementById('detail-sender');
        const timestampEl = document.getElementById('detail-timestamp');
        const contentEl = document.getElementById('detail-content');


        if (senderEl) senderEl.innerText = message.sender_username;
        if (timestampEl) timestampEl.innerText = new Date(message.timestamp).toLocaleString();
        if (contentEl) contentEl.innerText = message.text_content;

        // Display attachments if any
        const attachmentsSection = document.getElementById('attachments-section');
        const attachmentsList = document.getElementById('attachments-list');

        if (message.attachments && message.attachments.length > 0) {
            attachmentsSection.style.display = 'block';
            attachmentsList.innerHTML = message.attachments.map(att => `
                <div class="attachment-item">
                    <div class="attachment-info">
                        <div class="attachment-icon">
                            <i class="bi bi-file-earmark-fill"></i>
                        </div>
                        <div class="attachment-details">
                            <div class="attachment-name">${this.escapeHtml(att.filename)}</div>
                            <div class="attachment-meta">${this.escapeHtml(att.content_type)} • ${formatFileSize(att.size)}</div>
                        </div>
                    </div>
                    <button class="btn btn-sm btn-outline-primary download-attachment-btn"
                            data-attachment-id="${att.id}"
                            data-filename="${this.escapeHtml(att.filename)}">
                        <i class="bi bi-download"></i> Download
                    </button>
                </div>
            `).join('');

            // Attach event listeners to download buttons
            attachmentsList.querySelectorAll('.download-attachment-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    const attachmentId = btn.getAttribute('data-attachment-id');
                    const filename = btn.getAttribute('data-filename');
                    this.downloadAttachment(attachmentId, filename);
                });
            });
        } else {
            attachmentsSection.style.display = 'none';
        }
    },

    async markAsRead(messageId) {
        try {
            const response = await fetch(`/messages/mark-as-read?message_id=${messageId}`, {
                method: 'PATCH'
            });

            if (!response.ok) {
                const data = await response.json();
                handleAPIError(response, data);
                return false;
            }

            return true;
        } catch (error) {
            console.error('Error marking message as read:', error);
            return false;
        }
    },

    async handleSendMessage() {
        const recipients = document.getElementById('compose-recipients').value.trim();
        const textMessage = document.getElementById('compose-message').value.trim();
        const filesInput = document.getElementById('compose-files');

        if (!recipients || !textMessage) {
            showNotification('Please fill in all required fields.', 'warning');
            return;
        }

        // Parse recipients (comma-separated)
        const recipientsList = recipients.split(',').map(r => r.trim()).filter(r => r.length > 0);

        if (recipientsList.length === 0) {
            showNotification('Please specify at least one recipient.', 'warning');
            return;
        }

        // Check file count
        if (filesInput.files.length > 5) {
            showNotification('Maximum 5 files allowed.', 'error');
            return;
        }

        // Create FormData for multipart/form-data request
        const formData = new FormData();

        // Add message data as JSON string
        const messageData = {
            recipients: recipientsList,
            text_message: textMessage
        };
        formData.append('message_data', JSON.stringify(messageData));

        // Add files
        for (let i = 0; i < filesInput.files.length; i++) {
            formData.append('files', filesInput.files[i]);
        }

        try {
            const response = await fetch('/messages/send', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if (!response.ok) {
                // Display specific error message from backend
                const errorMessage = data?.detail || 'Failed to send message';
                showNotification(errorMessage, 'error');
                return;
            }

            // Check for missing users in the response (note: backend returns 'missing users' with space)
            const missingUsers = data['missing users'];
            if (missingUsers && Array.isArray(missingUsers) && missingUsers.length > 0) {
                const missingUsersList = missingUsers.join(', ');
                showNotification(`Message sent, but the following users were not found: ${missingUsersList}`, 'warning');
            } else {
                showNotification('Message sent successfully!', 'success');
            }

            // Close modal and reset form
            const modal = bootstrap.Modal.getInstance(document.getElementById('compose-modal'));
            modal.hide();
            document.getElementById('compose-form').reset();
            document.getElementById('file-count').innerText = 'No files selected';

            // Reload messages
            this.loadMessages();
        } catch (error) {
            console.error('Error sending message:', error);
            showNotification('Network error. Please try again.', 'error');
        }
    },

    async handleDeleteMessage() {
        if (!this.selectedMessageId) return;

        if (!confirm('Are you sure you want to delete this message?')) {
            return;
        }

        try {
            const response = await fetch(`/messages/delete?message_id=${this.selectedMessageId}`, {
                method: 'DELETE'
            });

            if (!response.ok) {
                const data = await response.json();
                if (handleAPIError(response, data)) {
                    return;
                }
                throw new Error('Failed to delete message');
            }

            showNotification('Message deleted successfully.', 'success');

            // Clear selection and reload
            this.selectedMessageId = null;
            document.getElementById('no-message-selected').style.display = 'flex';
            document.getElementById('message-detail').style.display = 'none';
            this.loadMessages();
        } catch (error) {
            console.error('Error deleting message:', error);
            showNotification('Failed to delete message.', 'error');
        }
    },

    async handleVerifySignature() {
        if (!this.selectedMessageId) return;

        try {
            const response = await fetch(`/messages/verify?message_id=${this.selectedMessageId}`, {
                method: 'POST'
            });

            const data = await response.json();

            if (!response.ok) {
                if (handleAPIError(response, data)) {
                    return;
                }
                throw new Error('Verification failed');
            }

            showNotification('✓ Message authenticity verified!', 'success');
        } catch (error) {
            console.error('Error verifying signature:', error);
            showNotification('Verification failed.', 'error');
        }
    },

    handleReply() {
        if (!this.selectedMessageId) return;

        const message = this.messages.find(m => m.message_id === this.selectedMessageId);
        if (!message) return;

        // Open compose modal with recipient pre-filled
        document.getElementById('compose-recipients').value = message.sender_username;

        const modal = new bootstrap.Modal(document.getElementById('compose-modal'));
        modal.show();
    },

    async downloadAttachment(attachmentId, filename) {
        try {
            const response = await fetch(`/messages/attachments?attachment_id=${attachmentId}`);

            if (!response.ok) {
                const data = await response.json();
                if (handleAPIError(response, data)) {
                    return;
                }
                throw new Error('Failed to download attachment');
            }

            // Create blob and trigger download
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);

            showNotification('Download started.', 'success');
        } catch (error) {
            console.error('Error downloading attachment:', error);
            showNotification('Failed to download attachment.', 'error');
        }
    },

    updatePagination() {
        const prevBtn = document.getElementById('prev-page-btn');
        const nextBtn = document.getElementById('next-page-btn');
        const pageInfo = document.getElementById('page-info');

        if (prevBtn) {
            prevBtn.disabled = this.currentPage === 1;
        }

        if (nextBtn) {
            // Disable next button if we got fewer messages than the page size
            nextBtn.disabled = this.messages.length < this.messagesPerPage;
        }

        if (pageInfo) {
            pageInfo.innerText = `Page ${this.currentPage}`;
        }
    },

    async handleLogout() {
        if (confirm('Are you sure you want to logout?')) {
            try {
                // Call the logout endpoint
                const response = await fetch('/auth/logout', {
                    method: 'POST'
                });

                const data = await response.json();

                if (!response.ok) {
                    handleAPIError(response, data);
                    return;
                }

                // Clear stored username
                localStorage.removeItem('username');

                showNotification(data.message || 'Logged out successfully', 'success');

                // Redirect to auth page after a short delay
                setTimeout(() => {
                    window.location.href = '/auth';
                }, 1000);
            } catch (error) {
                // Even if the API call fails, still log out locally
                console.error('Logout error:', error);
                localStorage.removeItem('username');
                showNotification('Logged out', 'info');
                setTimeout(() => {
                    window.location.href = '/auth';
                }, 1000);
            }
        }
    },

    show2FASetupModal() {
        const modal = new bootstrap.Modal(document.getElementById('2fa-setup-modal'));

        // Reset modal state
        document.getElementById('2fa-modal-password-form').style.display = 'block';
        document.getElementById('2fa-modal-qr-display').style.display = 'none';
        document.getElementById('2fa-modal-confirm-section').style.display = 'none';
        document.getElementById('2fa-modal-complete-btn').style.display = 'none';
        document.getElementById('2fa-modal-setup-form').reset();
        if (document.getElementById('2fa-modal-confirm-code')) {
            document.getElementById('2fa-modal-confirm-code').value = '';
        }

        modal.show();
    },

    async handle2FASetupFromInbox() {
        const password = document.getElementById('2fa-modal-password').value;

        try {
            const response = await fetch('/auth/2fa/setup', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password })
            });

            const data = await response.json();

            if (!response.ok) {
                handleAPIError(response, data);
                return;
            }

            // Display QR code and secret in modal
            document.getElementById('2fa-modal-password-form').style.display = 'none';
            document.getElementById('2fa-modal-qr-display').style.display = 'block';
            document.getElementById('2fa-modal-qr-image').src = `data:image/png;base64,${data.qr}`;
            document.getElementById('2fa-modal-secret').innerText = data.totp_secret;

            // Show the confirmation section and button
            document.getElementById('2fa-modal-confirm-section').style.display = 'block';
            document.getElementById('2fa-modal-complete-btn').style.display = 'block';
        } catch (error) {
            console.error('2FA setup error:', error);
            showNotification('Network error. Please try again.', 'error');
        }
    },

    async handle2FAConfirmFromInbox() {
        const code = document.getElementById('2fa-modal-confirm-code').value.trim();

        try {
            const response = await fetch('/auth/2fa/enable', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ code })
            });

            const data = await response.json();

            if (!response.ok) {
                handleAPIError(response, data);
                return;
            }

            showNotification('2FA enabled successfully!', 'success');
            const modal = bootstrap.Modal.getInstance(document.getElementById('2fa-setup-modal'));
            modal.hide();

            // Reset modal state
            document.getElementById('2fa-modal-password-form').style.display = 'block';
            document.getElementById('2fa-modal-qr-display').style.display = 'none';
            document.getElementById('2fa-modal-confirm-section').style.display = 'none';
            document.getElementById('2fa-modal-setup-form').reset();
            document.getElementById('2fa-modal-confirm-code').value = '';
        } catch (error) {
            console.error('2FA confirm error:', error);
            showNotification('Network error. Please try again.', 'error');
        }
    },

    escapeHtml(text) {
        const div = document.createElement('div');
        div.innerText = text;
        return div.innerHTML;
    }
};

// ========================================
// INITIALIZE APPLICATION
// ========================================

// Export modules to window object for access from HTML
window.authModule = authModule;
window.inboxModule = inboxModule;
window.showNotification = showNotification;
