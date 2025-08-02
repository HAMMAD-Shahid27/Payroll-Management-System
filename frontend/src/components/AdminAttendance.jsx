import React, { useEffect, useState } from 'react';
import axios from 'axios';
import './AdminAttendance.css';
import { useNavigate } from 'react-router-dom';

function AdminAttendance() {
  const [attendanceData, setAttendanceData] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchAttendance = async () => {
      try {
        const token = localStorage.getItem('token');
        const response = await axios.get('http://localhost:5000/admin/attendance', {
          headers: { Authorization: `Bearer ${token}` },
        });
        setAttendanceData(response.data);
      } catch (error) {
        console.error('Error fetching attendance data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchAttendance();
  }, []);

  return (
    <div className="admin-attendance-container">
      <header className="attendance-header">
        <h1>Employee Attendance</h1>
        <button onClick={() => navigate('/admin/dashboard')}>Back to Dashboard</button>
      </header>

      {loading ? (
        <p>Loading attendance records...</p>
      ) : (
        <table className="attendance-table">
          <thead>
            <tr>
              <th>Employee ID</th>
              <th>Name</th>
              <th>In Time</th>
              <th>Out Time</th>
            </tr>
          </thead>
          <tbody>
          {attendanceData.length > 0 ? (
            attendanceData.map((record, index) => (
                <tr key={index}>
                <td>{record.employee_id}</td>
                <td>{record.employee_name}</td>
                <td>{record.in_time ? new Date(record.in_time).toLocaleString() : 'N/A'}</td>
                <td>{record.out_time ? new Date(record.out_time).toLocaleString() : 'N/A'}</td>
                </tr>
            ))
            ) : (
            <tr>
                <td colSpan="4">No attendance records found.</td>
            </tr>
            )}

          </tbody>
        </table>
      )}
    </div>
  );
}

export default AdminAttendance;
