import React, { useEffect } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import './EmployeeNav.css';

function EmployeeNav() {
  const [, setName] = React.useState('Employee');
  const navigate = useNavigate();

  useEffect(() => {
    const storedName = localStorage.getItem('employeeName');
    if (storedName) {
      setName(storedName);
    }

    const handleStorageChange = () => {
      const newName = localStorage.getItem('employeeName') || 'Employee';
      setName(newName);
    };

    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('employeeName');
    navigate('/login/employee');
  };

  return (
    <div className="nav-container">
      <nav className="employee-nav">
        <div className="nav-header">
          <h1 className="nav-logo">Empoolyee's-Portal</h1>
        </div>

        <div className="nav-menu">
          <NavLink
            to="/employee/my-payroll"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <span className="nav-icon">💰</span>
            <span className="nav-text">My Payroll</span>
          </NavLink>

          <NavLink
            to="/employee/leave-request"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <span className="nav-icon">📨</span>
            <span className="nav-text">Request Leave</span>
          </NavLink>

          <NavLink
            to="/employee/my-leaves"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <span className="nav-icon">📋</span>
            <span className="nav-text">My Leaves</span>
          </NavLink>

          <NavLink
            to="/employee/attendance"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <span className="nav-icon">🕒</span>
            <span className="nav-text">Attendance</span>
          </NavLink>
        </div>
      </nav>

      <div className="logout-container">
        <button className="logout-btn" onClick={handleLogout}>
          <span className="logout-text">Logout</span>
        </button>
      </div>
    </div>
  );
}

export default EmployeeNav;
