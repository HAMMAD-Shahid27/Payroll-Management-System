import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './Login.css';

function Login({ isAdmin }) {
  const navigate = useNavigate();

  const [loginData, setLoginData] = useState({ username: '', email: '', password: '' });
  const [error, setError] = useState('');

  useEffect(() => {
    setLoginData({ username: '', email: '', password: '' });
    setError('');
  }, [isAdmin]);

const handleLogin = async (e) => {
  e.preventDefault();
  setError('');

  try {
    const res = await fetch(`http://localhost:5000/${isAdmin ? 'admin/login' : 'employee/login'}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(isAdmin ? {
        username: loginData.username,
        password: loginData.password
      } : {
        email: loginData.email,
        password: loginData.password
      }),
    });

    const data = await res.json();

    if (res.ok) {
      localStorage.setItem('token', data.token);
      localStorage.setItem('role', isAdmin ? 'admin' : 'employee');
      navigate(isAdmin ? '/admin/dashboard' : '/employee');
    } else {
      setError(data.message || 'Invalid credentials');
    }
  } catch (err) {
    setError('Server error. Please try again later.');
  }
};

  return (
    <div className="login-container">
      <div className="login-box">
        <h2>{isAdmin ? 'Admin Login' : 'Employee Login'}</h2>

        <form onSubmit={handleLogin} className="login-form">
          <div className="form-group">
            <label>{isAdmin ? 'Admin Username' : 'Employee Email'}</label>
            <input
              type={isAdmin ? 'text' : 'email'}
              autoComplete="off"
              value={isAdmin ? loginData.username : loginData.email}
              onChange={(e) =>
                setLoginData({
                  ...loginData,
                  [isAdmin ? 'username' : 'email']: e.target.value,
                })
              }
              placeholder={isAdmin ? 'Enter username' : 'Enter email'}
              required
            />
          </div>

          <div className="form-group">
            <label>Password</label>
            <input
              type="password"
              autoComplete="new-password"
              value={loginData.password}
              onChange={(e) => setLoginData({ ...loginData, password: e.target.value })}
              placeholder="Enter password"
              required
            />
          </div>

          {error && <div className="error-message">{error}</div>}

          <button type="submit" className="submit-btn">Login</button>

          {!isAdmin && (
            <div className="switch-link">
              Don't have an account?{' '}
              <span onClick={() => navigate('/signup')} style={{ cursor: 'pointer', color: '#4285f4', fontWeight: '600' }}>
                Sign up here
              </span>
            </div>
          )}
        </form>
      </div>
    </div>
  );
}

export default Login;
