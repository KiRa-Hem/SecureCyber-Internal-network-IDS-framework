class Auth {
    static API_BASE_URL = 'http://localhost:8765';
    
    static async login(username, password) {
        try {
            const formData = new FormData();
            formData.append('username', username);
            formData.append('password', password);
            
            const response = await fetch(`${this.API_BASE_URL}/auth/login`, {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            if (response.ok) {
                // Store tokens
                localStorage.setItem('access_token', data.access_token);
                localStorage.setItem('refresh_token', data.refresh_token);
                
                return { success: true };
            } else {
                return { success: false, message: data.detail || 'Login failed' };
            }
        } catch (error) {
            console.error('Login error:', error);
            return { success: false, message: 'An error occurred during login' };
        }
    }
    
    static async signup(username, email, password) {
        try {
            const response = await fetch(`${this.API_BASE_URL}/auth/signup`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, email, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                return { success: true };
            } else {
                return { success: false, message: data.detail || 'Signup failed' };
            }
        } catch (error) {
            console.error('Signup error:', error);
            return { success: false, message: 'An error occurred during signup' };
        }
    }
    
    static logout() {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        window.location.href = 'login.html';
    }
    
    static getToken() {
        return localStorage.getItem('access_token');
    }
    
    static isAuthenticated() {
        return !!this.getToken();
    }
    
    static async fetchWithAuth(url, options = {}) {
        const token = this.getToken();
        
        if (!token) {
            // Redirect to login if not authenticated
            window.location.href = 'login.html';
            return;
        }
        
        const headers = {
            ...options.headers,
            'Authorization': `Bearer ${token}`
        };
        
        try {
            const response = await fetch(url, {
                ...options,
                headers
            });
            
            // If token is expired or invalid, redirect to login
            if (response.status === 401) {
                this.logout();
                return;
            }
            
            return response;
        } catch (error) {
            console.error('Fetch error:', error);
            throw error;
        }
    }
    
    static createWebSocketWithAuth() {
        const token = this.getToken();
        
        if (!token) {
            // Redirect to login if not authenticated
            window.location.href = 'login.html';
            return null;
        }
        
        // Create WebSocket with token in query parameter
        const ws = new WebSocket(`ws://localhost:8765/ws?token=${token}`);
        
        // Handle authentication errors
        ws.addEventListener('close', (event) => {
            if (event.code === 1008) {  // Policy violation status code
                console.error('WebSocket authentication failed');
                this.logout();
            }
        });
        
        return ws;
    }
}

// Check authentication on page load
document.addEventListener('DOMContentLoaded', () => {
    // For pages that require authentication (like index.html)
    if (window.location.pathname.endsWith('index.html') && !Auth.isAuthenticated()) {
        window.location.href = 'login.html';
    }
});