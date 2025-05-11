import api from './api';

interface LoginRequest {
  email: string;
  password: string;
}

interface RegisterRequest {
  email: string;
  password: string;
  fullName: string;
  mobileNumber?: string;
  pin?: string;
  subscriptionId?: number;
}

export interface User {
  id: number;
  email: string;
  fullName: string;
  mobileNumber?: string;
  pin?: string;
  subscriptionId?: number;
}

export interface AuthResponse {
  message: string;
  token: string;
  user: User;
}

const authService = {
  login: async (data: LoginRequest): Promise<AuthResponse> => {
    try {
      const response = await api.post('/auth/login', data);
      
      // Ensure PIN is included in the user data
      const userData = {
        ...response.data.user,
        pin: response.data.user.pin || ''
      };
      
      // Save the token and user to localStorage
      localStorage.setItem('token', response.data.token);
      localStorage.setItem('user', JSON.stringify(userData));
      
      return {
        ...response.data,
        user: userData
      };
    } catch (error: any) {
      if (error.response) {
        throw error;
      }
      console.error('Login error:', error);
      throw new Error('Network error. Please try again later.');
    }
  },

  register: async (data: RegisterRequest): Promise<AuthResponse> => {
    try {
      const response = await api.post('/auth/register', data);
      
      // Ensure PIN is included in the user data
      const userData = {
        ...response.data.user,
        pin: response.data.user.pin || ''
      };
      
      // Save the token and user to localStorage
      localStorage.setItem('token', response.data.token);
      localStorage.setItem('user', JSON.stringify(userData));
      
      return {
        ...response.data,
        user: userData
      };
    } catch (error: any) {
      if (error.response) {
        throw error;
      }
      console.error('Registration error:', error);
      throw new Error('Network error. Please try again later.');
    }
  },

  getProfile: async (): Promise<User> => {
    try {
      const response = await api.get('/user/profile');
      
      // Get current user data from localStorage to preserve PIN
      const currentUser = localStorage.getItem('user');
      let currentUserData = {};
      
      if (currentUser) {
        try {
          currentUserData = JSON.parse(currentUser);
        } catch (e) {
          console.error('Error parsing current user data:', e);
        }
      }
      
      // Ensure PIN is preserved
      const userData = {
        ...response.data,
        pin: response.data.pin || (currentUserData as any).pin || ''
      };
      
      // Update localStorage with merged data
      localStorage.setItem('user', JSON.stringify(userData));
      
      return userData;
    } catch (error) {
      console.error('Profile fetch error:', error);
      throw error;
    }
  },

  updateProfile: async (data: Partial<User>): Promise<AuthResponse> => {
    try {
      const response = await api.put('/user/profile', data);
      
      // Get current user data from localStorage
      const currentUser = localStorage.getItem('user');
      let currentUserData = {};
      
      if (currentUser) {
        try {
          currentUserData = JSON.parse(currentUser);
        } catch (e) {
          console.error('Error parsing current user data:', e);
        }
      }
      
      // Ensure PIN is preserved
      const userData = {
        ...currentUserData,
        ...response.data.user,
        pin: data.pin || response.data.user.pin || (currentUserData as any).pin || ''
      };
      
      // Update localStorage
      localStorage.setItem('user', JSON.stringify(userData));
      
      return {
        ...response.data,
        user: userData
      };
    } catch (error) {
      console.error('Profile update error:', error);
      throw error;
    }
  },

  verifyOwner: async (mobileNumber: string, pin: string) => {
    try {
      const response = await api.post('/access/verify', { mobileNumber, pin });
      return response.data;
    } catch (error) {
      console.error('Owner verification error:', error);
      throw error;
    }
  },

  logout: () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  },

  googleLogin: () => {
    window.location.href = 'http://192.168.1.66:8000/api/auth/google';
  },

  handleGoogleCallback: async (token: string): Promise<AuthResponse> => {
    try {
      // Save the token and user to localStorage
      localStorage.setItem('token', token);
      
      // Get user profile
      const response = await api.get('/user/profile');
      const user = response.data;
      
      localStorage.setItem('user', JSON.stringify(user));
      
      return {
        message: 'Google login successful',
        token,
        user
      };
    } catch (error) {
      console.error('Google callback error:', error);
      throw error;
    }
  },
};

export default authService;
