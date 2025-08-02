import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './Login.css';

function Signup() {
  const navigate = useNavigate();

  const [signupData, setSignupData] = useState({
    name: '',
    email: '',
    password: '',
    phone: '',
  });

  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleSignup = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    try {
      const res = await fetch('http://localhost:5000/employee/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(signupData),
      });

      const data = await res.json();

      if (res.ok) {
        setSuccess('Signup successful! Redirecting to login...');
        setTimeout(() => navigate('/login/employee'), 1500);
      } else {
        setError(data.message || 'Signup failed.');
      }

      console.log('Signup response:', data);
    } catch (err) {
      console.error('Signup error:', err);
      setError('Server error. Please try again later.');
    }
  };

  return (
    <div className="login-container">
      <div className="login-box">
        <h2>Employee Signup</h2>

        <form onSubmit={handleSignup} className="login-form">
          <div className="form-group">
            <label>Full Name</label>
            <input
              type="text"
              value={signupData.name}
              onChange={(e) => setSignupData({ ...signupData, name: e.target.value })}
              placeholder="Enter your full name"
              required
            />
          </div>

          <div className="form-group">
            <label>Email</label>
            <input
              type="email"
              value={signupData.email}
              onChange={(e) => setSignupData({ ...signupData, email: e.target.value })}
              placeholder="Enter email"
              required
            />
          </div>

          <div className="form-group">
            <label>Phone Number</label>
            <input
              type="tel"
              value={signupData.phone}
              onChange={(e) => setSignupData({ ...signupData, phone: e.target.value })}
              placeholder="Enter phone number"
              required
            />
          </div>

          <div className="form-group">
            <label>Password</label>
            <input
              type="password"
              value={signupData.password}
              onChange={(e) => setSignupData({ ...signupData, password: e.target.value })}
              placeholder="Create password"
              required
            />
          </div>

          {error && <div className="error-message">{error}</div>}
          {success && <div className="success-message">{success}</div>}

          <button type="submit" className="submit-btn">Sign Up</button>

          <div className="switch-link">
            Already have an account?{' '}
            <span onClick={() => navigate('/login/employee')} style={{ cursor: 'pointer', color: '#4285f4', fontWeight: '600' }}>
              Login here
            </span>
          </div>
        </form>
      </div>
    </div>
  );
}

export default Signup;

