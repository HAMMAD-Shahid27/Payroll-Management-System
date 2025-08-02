import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './AdminLeaves.css';

function AdminLeaves() {
  const [leaves, setLeaves] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchPendingLeaves = async () => {
    setLoading(true);
    setError('');
    
    try {
      const token = localStorage.getItem('token');
      if (!token) throw new Error('No authentication token found');

      const response = await axios.get('http://localhost:5000/api/leave-requests/pending', {
        headers: { 'Authorization': `Bearer ${token}` },
        timeout: 5000
      });

      if (!Array.isArray(response.data)) {
        throw new Error('Invalid data format received');
      }

      setLeaves(response.data);
    } catch (err) {
      let errorMsg = 'Failed to fetch leave requests';
      if (err.response) {
        if (err.response.status === 404) {
          errorMsg = 'Endpoint not found - check server routes';
        } else if (err.response.status === 401) {
          errorMsg = 'Unauthorized - please login again';
        }
      }
      setError(errorMsg || err.message);
      console.error('Fetch error:', err);
    } finally {
      setLoading(false);
    }
  };


  const handleStatusUpdate = async (id, status) => {
    try {
      await axios.put(
        `http://localhost:5000/leaves/${id}/status`,
        { status },
        {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          }
        }
      );
      fetchPendingLeaves();
    } catch (err) {
      console.error('Update error:', err);
      alert(err.response?.data?.error || 'Failed to update status');
    }
  };

  useEffect(() => {
    fetchPendingLeaves();
  }, []);

  if (loading) return <div>Loading...</div>;
  if (error) return (
    <div>
      <p>Error: {error}</p>
      <button onClick={fetchPendingLeaves}>Retry</button>
    </div>
  );

  return (
    <div>
      {leaves.length === 0 ? (
  <div className="empty-state-container">
    <svg className="empty-state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
      <path strokeWidth="1.5" d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"></path>
    </svg>
    <h3 className="empty-state-title">No Pending Requests</h3>
    <p className="empty-state-message">
      No Leaves are Pending.
    </p>
    <button onClick={fetchPendingLeaves} className="refresh-btn empty-state-btn">
      Refresh List
    </button>
  </div>
) : (
        <table className="leaves-table">
          <thead>
            <tr>
              <th>Employee</th>
              <th>Date</th>
              <th>Reason</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {leaves.map(leave => (
              <tr key={leave.id}>
                <td>{leave.employee_name} ({leave.employee_email})</td>
                <td>{new Date(leave.date).toLocaleDateString()}</td>
                <td>{leave.reason}</td>
                <td className={`status-${leave.status.toLowerCase()}`}>
                  {leave.status}
                </td>
                <td>
                  <button 
                    onClick={() => handleStatusUpdate(leave.id, 'Approved')}
                    className="approve-btn"
                  >
                    Approve
                  </button>
                  <button 
                    onClick={() => handleStatusUpdate(leave.id, 'Rejected')}
                    className="reject-btn"
                  >
                    Reject
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default AdminLeaves;