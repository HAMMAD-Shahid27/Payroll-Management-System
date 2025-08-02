import React from 'react';
import { useNavigate } from 'react-router-dom';
import './Landingpage.css';

function LoginLand() {
  const navigate = useNavigate();

  return (
    <div className="landing-container">
      <div className="landing-box">
        <h2>Payroll Management System</h2>
        <div className="landing-toggle">
          <button className="toggle-btn" onClick={() => navigate('/login/admin')}>Admin Login</button>
          <button className="toggle-btn" onClick={() => navigate('/login/employee')}>Employee Login</button>
        </div>
        <div className="landing-footer">
          <p>Welcome to our platform. Choose your login type to proceed.</p>
        </div>
      </div>
    </div>
  );
}

export default LoginLand;
