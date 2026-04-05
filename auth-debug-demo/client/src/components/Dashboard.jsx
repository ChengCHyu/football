import React, { useEffect, useState } from 'react';
import { useAuth } from '../AuthContext';
import { protectedAPI } from '../api';

export default function Dashboard() {
  const { user, isAuthenticated, logout } = useAuth();
  const [data, setData] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    // BUG #F13: No guard — fires API call even when isAuthenticated is false,
    //           causing an immediate 401 on every mount
    const fetchData = async () => {
      try {
        const res = await protectedAPI.dashboard();
        setData(res.data);
      } catch (err) {
        setError('Failed to load dashboard');
      }
    };
    fetchData();
  }, []);  // BUG #F14: Missing isAuthenticated dependency — doesn't re-fetch on login

  // BUG #F15: No redirect for unauthenticated users — renders empty dashboard
  return (
    <div>
      <h2>Dashboard</h2>
      {user && <p>Welcome, {user.name || user.email}</p>}
      <button onClick={logout}>Logout</button>
      {error && <div className="error">{error}</div>}
      {data && <pre>{JSON.stringify(data, null, 2)}</pre>}
    </div>
  );
}
