import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import './AdminDashBoard.css';

function AdminDashboard() {
  const navigate = useNavigate();
  const [pendingLeaves, setPendingLeaves] = useState(0);
  const [employeeCount, setEmployeeCount] = useState(0); 
  const [loading, setLoading] = useState(true);


  const handleLogout = () => {
    localStorage.removeItem('token');
    navigate('/login/admin');
  };

  const fetchPendingLeavesCount = async () => {
    try {
      const token = localStorage.getItem('token');
      if (!token) throw new Error('No authentication token found');

      const response = await axios.get('http://localhost:5000/api/leave-requests/pending/count', {
        headers: { 'Authorization': `Bearer ${token}` },
        timeout: 5000
      });

      setPendingLeaves(response.data.count || 0);
    } catch (err) {
      console.error('Error fetching pending leaves count:', err);
    }
  };

  // NEW: Function to fetch employee count
  const fetchEmployeeCount = async () => {
    try {
      const token = localStorage.getItem('token');
      if (!token) throw new Error('No authentication token found');
  
      const response = await axios.get('http://localhost:5000/api/employees/count', {
        headers: { 'Authorization': `Bearer ${token}` },
        timeout: 5000
      });
  
      setEmployeeCount(response.data.count || 0);
      setLoading(false); // Set loading to false once data is fetched
    } catch (err) {
      console.error('Error fetching employee count:', err);
      setLoading(false); // Set loading to false in case of error
    }
  };
  
  

  useEffect(() => {
    fetchPendingLeavesCount();
    fetchEmployeeCount(); 
    const interval = setInterval(() => {
      fetchPendingLeavesCount();
      fetchEmployeeCount();
    }, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="admin-dashboard-container">
      <header className="dashboard-header">
        <div className="header-content">
          <h1 className="system-title">Cloud Payroll System</h1>
          <p className="system-subtitle">Administrator Dashboard</p>
          <nav className="header-nav">
            <button onClick={() => navigate('/admin/payroll')}>Payroll</button>
            <button onClick={() => navigate('/admin/employees')}>Employees</button>
            <button onClick={() => navigate('/admin/leaves')}>Leaves</button>
            <button onClick={() => navigate('/admin/attendance')}>Attendance</button>
            <button className="logout-button" onClick={handleLogout}>Logout</button>
          </nav>
        </div>
      </header>

      <section className="stats-section">
      <div className="stats-container">
        {/* Pending Leaves Card */}
        <div className="stat-card alert" onClick={() => navigate('/admin/leaves')}>
          <div className="stat-content">
            <h3>Pending Leaves</h3>
            <p className="stat-value">{pendingLeaves}</p>
          </div>
        </div>

        {/* Total Employees Card */}
        <div className="stat-card" onClick={() => navigate('/admin/employees')}>
          <div className="stat-content">
            <h3>Total Employees</h3>
            <p className="stat-value">
              {loading ? '...' : employeeCount}
            </p>
          </div>
        </div>
      </div>
    </section>

      <section className="quick-links-section">
        <h2 className="section-title">Quick Links</h2>
        <div className="dashboard-actions">
          <div className="dashboard-card" onClick={() => navigate('/admin/payroll')}>
            <div className="card-icon">💰</div>
            <h3>Payroll Management</h3>
            <p>Create and manage employee payroll</p>
          </div>

          <div className="dashboard-card" onClick={() => navigate('/admin/employees')}>
            <div className="card-icon">👥</div>
            <h3>Employee Management</h3>
            <p>View and manage employee records</p>
          </div>

          <div className="dashboard-card" onClick={() => navigate('/admin/leaves')}>
            <div className="card-icon">🗓️</div>
            <h3>Leave Requests</h3>
            <p>Approve or reject leave applications</p>
          </div>

          <div className="dashboard-card" onClick={() => navigate('/admin/attendance')}>
            <div className="card-icon">📋</div>
            <h3>Attendance</h3>
            <p>Track and manage employee attendance</p>
          </div>
        </div>
      </section>
    </div>
  );
}

export default AdminDashboard;
