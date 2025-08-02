import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './EmployeeLeaves.css';

function EmployeeLeave() {
  const [date, setDate] = useState('');
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);

    const token = localStorage.getItem('token');
    if (!token) {
      setError('Please login first');
      setIsSubmitting(false);
      return;
    }

    try {
      const response = await axios.post(
        'http://localhost:5000/leave-requests',
        { date, reason },
        {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          }
        }
      );

      if (response.data.message) {
        alert(response.data.message);
        setDate('');
        setReason('');
        // Optionally refresh the leave requests list
        navigate('/employee/my-leaves');
      }
    } catch (err) {
      console.error('Leave request error:', err);
      setError(err.response?.data?.error || 'Failed to submit leave request');
      if (err.response?.data?.details) {
        console.error('Error details:', err.response.data.details);
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="leave-request-container">
      <h2>Submit Leave Request</h2>
      {error && <div className="error-message">{error}</div>}
      
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="date">Leave Date:</label>
          <input
            type="date"
            id="date"
            value={date}
            onChange={(e) => setDate(e.target.value)}
            required
            min={new Date().toISOString().split('T')[0]} // Prevent past dates
          />
        </div>

        <div className="form-group">
          <label htmlFor="reason">Reason:</label>
          <textarea
            id="reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            required
            rows={4}
          />
        </div>

        <button type="submit" disabled={isSubmitting}>
          {isSubmitting ? 'Submitting...' : 'Submit Request'}
        </button>
      </form>
    </div>
  );
}

export default EmployeeLeave;