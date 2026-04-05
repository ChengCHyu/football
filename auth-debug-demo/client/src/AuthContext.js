import React, { createContext, useContext, useState, useEffect } from 'react';
import { authAPI } from './api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // ============================================================
  // BUG #F5: checkAuth reads from 'token' (correct) but the
  //          axios interceptor reads 'user_token' — so even if
  //          this function finds a token, API calls still fail
  // ============================================================
  useEffect(() => {
    const checkAuth = async () => {
      const token = localStorage.getItem('token');
      if (token) {
        try {
          const res = await authAPI.me();
          setUser(res.data.user);
        } catch {
          // BUG #F6: On error clears 'token' but interceptor uses 'user_token'
          //          — stale 'user_token' may remain in storage
          localStorage.removeItem('token');
          setUser(null);
        }
      }
      setLoading(false);
    };
    checkAuth();
  }, []);

  const login = async (email, password) => {
    const res = await authAPI.login({ email, password });
    // BUG #F7: Saves token to 'token' but axios interceptor reads 'user_token'
    localStorage.setItem('token', res.data.token);
    setUser(res.data.user);
    return res.data;
  };

  const register = async (email, password, name) => {
    const res = await authAPI.register({ email, password, name });
    // Same inconsistency — saves as 'token'
    localStorage.setItem('token', res.data.token);
    setUser(res.data.user);
    return res.data;
  };

  const logout = async () => {
    await authAPI.logout();
    // BUG #F8: Removes 'token' but 'user_token' (if it existed) lingers
    localStorage.removeItem('token');
    setUser(null);
    // BUG #F9: Does not redirect to /login — user stays on protected page
  };

  // BUG #F10: isAuthenticated is derived from `user` state, but
  //           `user` is only populated on mount if /me succeeds,
  //           which it won't because of the header / key mismatches
  const value = {
    user,
    loading,
    isAuthenticated: !!user,
    login,
    register,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
