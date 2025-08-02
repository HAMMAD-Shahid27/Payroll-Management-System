import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './MyLeaves.css';

function MyLeaves() {
  const [leaves, setLeaves] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const fetchLeaves = async () => {
      const token = localStorage.getItem('token');
      if (!token) {
        setError('Please login first');
        setLoading(false);
        return;
      }

      try {
        const response = await axios.get('http://localhost:5000/leave-requests/employee', {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        setLeaves(response.data);
      } catch (err) {
        console.error('Error fetching leaves:', err);
        setError(err.response?.data?.error || 'Failed to fetch leave requests');
      } finally {
        setLoading(false);
      }
    };

    fetchLeaves();
  }, []);

  if (loading) return <div>Loading your leave requests...</div>;
  if (error) return <div className="error-message">{error}</div>;

  return (
    <div className="my-leaves-container">
      <h2>My Leave Requests</h2>
      
      {leaves.length === 0 ? (
        <p>You have no leave requests yet.</p>
      ) : (
        <table className="leaves-table">
          <thead>
            <tr>
              <th>Date</th>
              <th>Reason</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {leaves.map((leave) => (
              <tr key={leave.id} className={`status-${leave.status.toLowerCase()}`}>
                <td>{new Date(leave.date).toLocaleDateString()}</td>
                <td>{leave.reason}</td>
                <td>{leave.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default MyLeaves;