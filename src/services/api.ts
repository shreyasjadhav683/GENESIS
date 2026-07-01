import axios from 'axios';

// Automatically point to the same host as the frontend, but on port 8000 (backend)
const API_URL = `${window.location.protocol}//${window.location.hostname}:8000/api/v1`;

export const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add token
api.interceptors.request.use(
  (config: any) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error: any) => Promise.reject(error)
);

// Response interceptor to handle 401/403
api.interceptors.response.use(
  (response: any) => response,
  (error: any) => {
    if (error.response && (error.response.status === 401 || error.response.status === 403)) {
      // Clear token and redirect to login if session is invalid
      localStorage.removeItem('token');
      // Prevent redirect loop if already on login page
      if (!window.location.pathname.includes('/login')) {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);
