import axios from 'axios';
import type {
  LoginRequest,
  LoginResponse,
  User,
  Scan,
  // Vulnerability,
  CWE
} from '../types';

const api = axios.create({
  baseURL: '/api',  // nginx проксирует на backend:8000
  headers: {
    'Content-Type': 'application/json',
  },
});

// Interceptor для JWT токена
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  const currentLang = localStorage.getItem('i18nextLng') || 'ru';
  config.headers['Accept-Language'] = currentLang === 'en' ? 'en' : 'ru';
  return config;
});

// Interceptor для обработки 401
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Auth API
export const authAPI = {
  login: async (credentials: LoginRequest): Promise<LoginResponse> => {    
    const response = await api.post('/auth/login', {
      username: credentials.username,
      password: credentials.password,
    });
    return response.data;
  },
};

// Scans API
export const scansAPI = {
  getAll: async (): Promise<Scan[]> => { // TODO: pagination via limit/offset
    const response = await api.get('/scans/');
    return response.data;
  },
  
  getById: async (id: number): Promise<Scan> => {
    const response = await api.get(`/scans/${id}`);
    return response.data;
  },
  
  create: async (targetUrl: string, /*scanType: string*/): Promise<Scan> => {
    const response = await api.post('/scans/', {
      target_url: targetUrl,
      // scan_type: scanType, // TODO: scan_type backend
    });
    return response.data;
  },
  
  // delete: async (id: number): Promise<void> => {
  //   await api.delete(`/scans/${id}`);
  // },

  // В scansAPI добавь:
  createSAST: async (file: File): Promise<Scan> => {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await api.post('/scans/sast', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

};

// Users API (только для ADMIN)
export const usersAPI = {
  getAll: async (): Promise<User[]> => {
    const response = await api.get('/users/');
    return response.data;
  },
  
  create: async (userData: {
    username: string;
    email: string;
    password: string;
    role: string;
  }): Promise<User> => {
    const response = await api.post('/users/', userData);
    return response.data;
  },

  getCurrentUser: async (): Promise<User> => {
    const response = await api.get('/users/me');
    return response.data;
  }
};

// CWE API
export const cweAPI = {
  getAll: async (): Promise<CWE[]> => {
    const response = await api.get('/cwe/');
    return response.data;
  },
  
  getById: async (cweId: string): Promise<CWE> => {
    const response = await api.get(`/cwe/${cweId}`);
    return response.data;
  },
};


export default api;
