import React, { useState, useEffect } from 'react';
import './EmployeeAttendance.css';

function EmployeeAttendance() {
  const [inTime, setInTime] = useState('');
  const [outTime, setOutTime] = useState('');
  const today = new Date().toISOString().split('T')[0];

  useEffect(() => {
    const savedIn = localStorage.getItem(`attendanceIn_${today}`);
    const savedOut = localStorage.getItem(`attendanceOut_${today}`);
    if (savedIn) setInTime(savedIn);
    if (savedOut) setOutTime(savedOut);
  }, [today]);

  useEffect(() => {
    if (inTime && outTime) {

      const sendAttendance = async () => {
        try {
          const token = localStorage.getItem('token');
          console.log('Sending inTime:', inTime, 'outTime:', outTime);
          const response = await fetch('http://localhost:5000/employee/attendance', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ inTime, outTime })
          });
      
          const data = await response.json();
          if (response.ok) {
            console.log('✅', data.message);
          } else {
            console.error('❌', data.error);
          }
        } catch (err) {
          console.error('🚨 Error sending attendance:', err);
        }
      };
      sendAttendance();
    }
  }, [inTime, outTime]);

  const handleInChange = (e) => {
    const value = e.target.value;
    setInTime(value);
    localStorage.setItem(`attendanceIn_${today}`, value);
  };

  const handleOutChange = (e) => {
    const value = e.target.value;
    setOutTime(value);
    localStorage.setItem(`attendanceOut_${today}`, value);
  };

  const handleReset = () => {
    setInTime('');
    setOutTime('');
    localStorage.removeItem(`attendanceIn_${today}`);
    localStorage.removeItem(`attendanceOut_${today}`);
  };

  return (
    <div className="attendance-container">
      <h2 className="attendance-title">📅 Attendance - {today}</h2>

      <div className="attendance-input-group">
        <label><strong>In Time:</strong></label>
        <input
          type="datetime-local"
          value={inTime}
          onChange={handleInChange}
        />
      </div>

      <div className="attendance-input-group">
        <label><strong>Out Time:</strong></label>
        <input
          type="datetime-local"
          value={outTime}
          onChange={handleOutChange}
          disabled={!inTime}
        />
      </div>

      <div className="attendance-actions">
        <button 
          className="reset-button" 
          onClick={handleReset}
          disabled={!inTime && !outTime}
        >
          Reset Attendance
        </button>
      </div>
    </div>
  );
}

export default EmployeeAttendance;
