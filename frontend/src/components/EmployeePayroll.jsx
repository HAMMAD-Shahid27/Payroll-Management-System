import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { jwtDecode } from 'jwt-decode';
import { useNavigate } from 'react-router-dom';
import EmployeeNav from './EmployeeNav';
import './EPayroll.css';

function EmployeePayroll() {
  const [payrolls, setPayrolls] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const controller = new AbortController();
    let isMounted = true;
  
    const fetchPayrolls = async () => {
      const token = localStorage.getItem('token');
      if (!token) {
        navigate('/login/employee');
        return;
      }
  
      let employeeId;
      try {
        const decoded = jwtDecode(token);
        employeeId = decoded.id; // Assuming the token contains `id` field
        if (!employeeId) throw new Error('Invalid token, no employee ID found');
      } catch (err) {
        console.error('Invalid token', err);
        localStorage.removeItem('token');
        navigate('/login/employee');
        return;
      }
  
      setIsLoading(true);
      setError(null);
  
      try {
        const response = await axios.get(`http://localhost:5000/payroll/${employeeId}`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal
        });
  
        if (isMounted) {
          setPayrolls(response.data);
        }
      } catch (error) {
        if (!isMounted || axios.isCancel(error)) return;
  
        console.error('Fetch error:', error);
        if (error.response?.status === 401) {
          localStorage.removeItem('token');
          navigate('/login/employee');
        } else {
          setError(error.response?.data?.error || error.message || 'Failed to load payroll data');
        }
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    };
  
    fetchPayrolls();
  
    return () => {
      isMounted = false;
      controller.abort();
    };
  }, [navigate]);

  const formatDate = (dateString) => {
    try {
      return new Date(dateString).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      });
    } catch {
      return 'Invalid date';
    }
  };

  const formatCurrency = (amount) => {
    const num = Number(amount);
    if (isNaN(num)) return '£0.00';
    
    return new Intl.NumberFormat('en-GB', { 
      style: 'currency',
      currency: 'GBP',
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    }).format(num);
  };

  const calculateValues = (payroll) => {
    const basic = Number(payroll.basic_salary) || 0;
    const bonus = Number(payroll.bonus) || 0;
    const deductions = Number(payroll.deductions) || 0;
    const taxPercent = Number(payroll.tax_percent) || 0;
    
    const taxableAmount = basic + bonus;
    const taxAmount = taxableAmount * (taxPercent / 100);
    const netSalary = taxableAmount - taxAmount - deductions;

    return {
      basic,
      bonus,
      deductions,
      taxPercent,
      taxAmount,
      netSalary
    };
  };

  const handleRetry = () => {
    setError(null);
    setIsLoading(true);
  };

  return (
    <div className="employee-payroll-container">
      <EmployeeNav />
      
      <main className="payroll-main-content">
        <div className="payroll-history-container">
          <h1 className="payroll-title">Payroll History</h1>
          
          {isLoading ? (
            <div className="loading-state">
              <div className="spinner"></div>
              <p>Loading payroll records...</p>
            </div>
          ) : error ? (
            <div className="error-state">
              <p>{error}</p>
              <button onClick={handleRetry} className="retry-btn">
                Retry
              </button>
            </div>
          ) : payrolls.length === 0 ? (
            <div className="empty-state">
              <p>No payroll records available</p>
            </div>
          ) : (
            <div className="table-scroll-container">
              <table className="payroll-table">
                <thead>
                  <tr>
                    <th>Payment Date</th>
                    <th>Basic Salary</th>
                    <th>Bonus</th>
                    <th>Deductions</th>
                    <th>Tax</th>
                    <th>Net Salary</th>
                  </tr>
                </thead>
                <tbody>
                  {payrolls.map((payroll) => {
                    const { netSalary, taxPercent, taxAmount } = calculateValues(payroll);
                    return (
                      <tr key={payroll.id || payroll.payment_date}>
                        <td>{formatDate(payroll.payment_date)}</td>
                        <td>{formatCurrency(payroll.basic_salary)}</td>
                        <td>{formatCurrency(payroll.bonus)}</td>
                        <td>{formatCurrency(payroll.deductions)}</td>
                        <td>
                          {formatCurrency(taxAmount)}
                          {taxPercent > 0 && (
                            <span className="tax-percent"> ({taxPercent}%)</span>
                          )}
                        </td>
                        <td className={`net-salary ${netSalary < 0 ? 'negative' : ''}`}>
                          {formatCurrency(netSalary)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

export default EmployeePayroll;