const API_URL = 'http://localhost:5000/api/auth';

class AuthService {
    // Register user
    async register(userData) {
        try {
            const response = await fetch(`${API_URL}/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(userData),
            });

            const data = await response.json();

            if (data.success && data.user.token) {
                localStorage.setItem('token', data.user.token);
                localStorage.setItem('user', JSON.stringify(data.user));
            }

            return data;
        } catch (error) {
            throw new Error('Network error during registration');
        }
    }

    // Login user
    async login(credentials) {
        try {
            const response = await fetch(`${API_URL}/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(credentials),
            });

            const data = await response.json();

            if (data.success && data.user.token) {
                localStorage.setItem('token', data.user.token);
                localStorage.setItem('user', JSON.stringify(data.user));
            }

            return data;
        } catch (error) {
            throw new Error('Network error during login');
        }
    }

    // Get user profile
    async getProfile() {
        try {
            const token = this.getToken();
            const response = await fetch(`${API_URL}/profile`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                },
            });

            return await response.json();
        } catch (error) {
            throw new Error('Network error fetching profile');
        }
    }

    // Update user profile
    async updateProfile(userData) {
        try {
            const token = this.getToken();
            const response = await fetch(`${API_URL}/profile`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(userData),
            });

            const data = await response.json();

            if (data.success && data.user.token) {
                localStorage.setItem('token', data.user.token);
                localStorage.setItem('user', JSON.stringify(data.user));
            }

            return data;
        } catch (error) {
            throw new Error('Network error updating profile');
        }
    }

    // Logout
    logout() {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
    }

    // Get current user
    getCurrentUser() {
        const user = localStorage.getItem('user');
        return user ? JSON.parse(user) : null;
    }

    // Get token
    getToken() {
        return localStorage.getItem('token');
    }

    // Check if user is authenticated
    isAuthenticated() {
        const token = this.getToken();
        if (!token) return false;

        try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            const currentTime = Date.now() / 1000;
            return payload.exp > currentTime;
        } catch (error) {
            return false;
        }
    }
}

export default new AuthService();