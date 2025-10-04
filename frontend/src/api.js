import axios from "axios";

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || "https://pci-monitor-app-production-46fc.up.railway.app";

// Create axios instance with base config
export const api = axios.create({
  baseURL: API_BASE_URL,
});

// Set up request interceptor
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("auth_token");
    if (token && !config.url.includes('/login')) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Set up response interceptor
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && !error.config.url.includes('/login')) {
      localStorage.removeItem("auth_token");
      localStorage.removeItem("username");
      window.location.reload();
    }
    return Promise.reject(error);
  }
);