import axios from 'axios';
import { toast } from 'sonner';

// Get the server's IP address from the current URL
const getServerIP = () => {
  // Always return our fixed IP address
  return '34.132.75.76';
};

const SERVER_IP = getServerIP();
export const API_URL = `http://${SERVER_IP}:7000/api`;
console.log('API URL configured as:', API_URL);

// Function to check if token is expired
const isTokenExpired = (token) => {
  if (!token) return true;
  
  try {
    // Get the expiration time from the token
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const payload = JSON.parse(window.atob(base64));
    
    // JWT exp is in seconds, Date.now() is in milliseconds
    const expirationTime = payload.exp * 1000;
    return Date.now() >= expirationTime;
  } catch (e) {
    console.error('Error checking token expiration:', e);
    return true; // Assume expired if we can't parse it
  }
};

// Function to get user info from token
const getUserInfoFromToken = (token) => {
  if (!token) return null;
  
  try {
    // Parse the token payload
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(window.atob(base64));
  } catch (e) {
    console.error('Error extracting user info from token:', e);
    return null;
  }
};

// Check if the current token is about to expire and needs a refresh
const shouldRefreshToken = (token) => {
  if (!token) return false;
  
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const payload = JSON.parse(window.atob(base64));
    
    // If token is less than 30 minutes from expiring, refresh it
    const expirationTime = payload.exp * 1000;
    const thirtyMinutes = 30 * 60 * 1000;
    
    return (expirationTime - Date.now()) < thirtyMinutes;
  } catch (e) {
    return false;
  }
};

// Create API instance
const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 15000, // 15 second timeout
  withCredentials: true // Enable sending cookies
});

// Add token to requests if available
api.interceptors.request.use(
  async (config) => {
    const token = localStorage.getItem('token');
    const ownerToken = localStorage.getItem('ownerToken');
    
    // Special case: Don't add authentication for owner verification endpoint
    if (config.url?.includes('/access/verify')) {
      console.log('Skipping auth for owner verification');
      // Remove Authorization header if it exists
      if (config.headers.Authorization) {
        delete config.headers.Authorization;
      }
      return config;
    }
    
    // Check if token is expired
    if (token && isTokenExpired(token)) {
      console.warn('Token is expired, clearing authentication data');
      // Clear expired tokens
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      
      // Redirect to login page if not already there
      if (!window.location.pathname.includes('/login') && !window.location.pathname.includes('/register')) {
        toast.error('Your session has expired. Please log in again.');
        window.location.href = '/login';
        // This will abort the current request
        return Promise.reject(new Error('Authentication expired'));
      }
    }
    
    // Handle owner token or regular user token
    if (ownerToken) {
      config.headers.Authorization = `Bearer ${ownerToken}`;
    } else if (token) {
      config.headers.Authorization = `Bearer ${token}`;
      
      // Only attempt refresh for authenticated user routes, not authentication routes
      if (shouldRefreshToken(token) && !config.url?.includes('/auth/')) {
        // We'll handle this in a future enhancement - ideally implement a token refresh endpoint
        console.log('Token will expire soon, should implement refresh mechanism');
      }
    }
    
    // Log user ID from token for debugging
    const userInfo = getUserInfoFromToken(token || ownerToken);
    const userId = userInfo?.id;
    
    console.log('Making API request:', {
      method: config.method?.toUpperCase(),
      url: config.url,
      baseURL: config.baseURL,
      userId: userId || 'not authenticated',
      headers: { 
        ...config.headers,
        Authorization: config.headers.Authorization ? 'Bearer [TOKEN]' : 'None' // Don't log the actual token
      },
      data: config.data,
      fullUrl: `${config.baseURL}${config.url}`
    });
    return config;
  },
  (error) => {
    console.error('Request interceptor error:', error);
    return Promise.reject(error);
  }
);

// Add response interceptor for better error handling
api.interceptors.response.use(
  (response) => {
    console.log('API Response:', {
      status: response.status,
      url: response.config.url,
      data: response.data
    });
    return response;
  },
  (error) => {
    console.error('API Error:', {
      status: error.response?.status,
      data: error.response?.data,
      message: error.message,
      config: {
        url: error.config?.url,
        method: error.config?.method,
        baseURL: error.config?.baseURL,
        fullUrl: `${error.config?.baseURL}${error.config?.url}`
      }
    });

    // Handle specific authentication errors
    if (error.response?.status === 401) {
      // Just show error message, no redirect
      toast.error(error.response.data.message || 'Authentication failed');
    }
    else if (error.response?.status === 403) {
      toast.error('Your session token is invalid. Please log in again.');
      localStorage.removeItem('token');
      localStorage.removeItem('user');
    }
    else if (error.response?.status === 404 && error.response?.data?.message?.includes('User not found')) {
      toast.error('Your account information was not found. Please log in again.');
      localStorage.removeItem('token');
      localStorage.removeItem('user');
    }
    // Handle network errors
    else if (error.code === 'ERR_NETWORK') {
      toast.error('Network error. Please check your connection and try again.');
    } else if (error.response?.data?.message) {
      toast.error(error.response.data.message);
    } else {
      toast.error('An error occurred. Please try again.');
    }

    return Promise.reject(error);
  }
);

export default api;