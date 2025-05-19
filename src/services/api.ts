import axios from 'axios';
import { toast } from 'sonner';

// Get the API URL from environment variables
const API_URL = 'https://api.samirmajhi369.com.np/api';

// Create axios instance with default config
const api = axios.create({
    baseURL: API_URL,
    timeout: 15000,
    headers: {
        'Content-Type': 'application/json'
    }
});

// Add request interceptor for authentication
api.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem('token');
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

// Add response interceptor for error handling
api.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response) {
            // Handle specific error cases
            switch (error.response.status) {
                case 401:
                    toast.error('Session expired. Please login again.');
                    localStorage.removeItem('token');
                    window.location.href = '/login';
                    break;
                case 403:
                    toast.error('Access denied.');
                    break;
                case 404:
                    toast.error('Resource not found.');
                    break;
                case 429:
                    toast.error('Too many requests. Please try again later.');
                    break;
                default:
                    toast.error(error.response.data?.message || 'An error occurred.');
            }
        } else if (error.request) {
            toast.error('Network error. Please check your connection.');
        } else {
            toast.error('An unexpected error occurred.');
        }
        return Promise.reject(error);
    }
);

export default api;
export { API_URL };