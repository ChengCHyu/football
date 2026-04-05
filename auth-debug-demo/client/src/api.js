import axios from 'axios';

// ============================================================
// BUG #F1: API base URL points to wrong port (3000 instead of
//          3001 where the server actually listens)
// ============================================================
const API = axios.create({
  baseURL: 'http://localhost:3000/api',  // should be 3001
  withCredentials: true,
});

// ============================================================
// Request interceptor — attaches token
// BUG #F2: Reads from localStorage key 'user_token' but login
//          saves under 'token' — interceptor never finds it
// ============================================================
API.interceptors.request.use((config) => {
  const token = localStorage.getItem('user_token');  // should be 'token'
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// ============================================================
// Response interceptor — handle 401
// BUG #F3: On 401, tries to refresh but uses the same wrong
//          localStorage key; also doesn't redirect on failure
// ============================================================
API.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      const token = localStorage.getItem('user_token');  // wrong key
      if (token) {
        try {
          const res = await axios.post('http://localhost:3000/api/auth/refresh', { token });
          localStorage.setItem('user_token', res.data.token);  // wrong key
          error.config.headers.Authorization = `Bearer ${res.data.token}`;
          return axios(error.config);
        } catch {
          // BUG #F4: Should clear token + redirect to /login, but silently swallows error
          console.log('Refresh failed');
        }
      }
    }
    return Promise.reject(error);
  }
);

export const authAPI = {
  register: (data) => API.post('/auth/register', data),
  login:    (data) => API.post('/auth/login', data),
  me:       ()     => API.get('/auth/me'),
  logout:   ()     => API.post('/auth/logout'),
};

export const protectedAPI = {
  dashboard: () => API.get('/protected/dashboard'),
};

export default API;
