
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './payroll.css';

function CreatePayroll() {
  const [employees, setEmployees] = useState([]);
  const [selectedEmployee, setSelectedEmployee] = useState('');
  const [basicSalary, setBasicSalary] = useState('');
  const [bonus, setBonus] = useState('');
  const [deductions, setDeductions] = useState('');
  const [taxPercent, setTaxPercent] = useState('');
  const [message, setMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();

  const getAuthToken = () => {
    return localStorage.getItem('token') || sessionStorage.getItem('token');
  };

  useEffect(() => {
    const fetchEmployees = async () => {
      const token = getAuthToken();
      if (!token) {
        navigate('/login');
        return;
      }

      setIsLoading(true);
      try {
        const response = await axios.get('http://localhost:5000/employees', {
          headers: {
            Authorization: `Bearer ${token}`
          }
        });
        setEmployees(response.data);
      } catch (error) {
        console.error('Error fetching employees:', error);
        if (error.response?.status === 401) {
          localStorage.removeItem('token');
          sessionStorage.removeItem('token');
          navigate('/login');
        } else {
          setMessage('Failed to load employees. Please try again later.');
        }
      } finally {
        setIsLoading(false);
      }
    };

    fetchEmployees();
  }, [navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const token = getAuthToken();
    
    if (!token) {
      navigate('/login');
      return;
    }

    if (!selectedEmployee || 
        isNaN(basicSalary) || basicSalary <= 0 ||
        isNaN(bonus) || bonus < 0 ||
        isNaN(deductions) || deductions < 0 ||
        isNaN(taxPercent) || taxPercent < 0 || taxPercent > 100) {
      setMessage('❗ Please fill out all fields with valid values.');
      return;
    }

    const payrollData = {
      employeeId: parseInt(selectedEmployee),
      basicSalary: parseFloat(basicSalary),
      bonus: parseFloat(bonus),
      deductions: parseFloat(deductions),
      taxPercent: parseFloat(taxPercent),
    };

    setIsLoading(true);
    try {
      const response = await axios.post('http://localhost:5000/payroll', payrollData, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      
      const employee = employees.find(e => e.id === parseInt(selectedEmployee));
      
      navigate('/payroll-details', { 
        state: {
          payroll: response.data,
          employee: employee,
          calculatedValues: {
            taxAmount: (parseFloat(basicSalary) + parseFloat(bonus)) * (parseFloat(taxPercent) / 100),
            netSalary: (parseFloat(basicSalary) + parseFloat(bonus)) - parseFloat(deductions) - ((parseFloat(basicSalary) + parseFloat(bonus)) * (parseFloat(taxPercent) / 100))
          }
        }
      });
      
    } catch (error) {
      console.error('Payroll creation error:', error);
      
      if (error.response?.status === 401) {
        setMessage('❌ Session expired. Redirecting to login...');
        localStorage.removeItem('token');
        sessionStorage.removeItem('token');
        setTimeout(() => navigate('/login'), 1500);
      } else if (error.response?.data?.error) {
        setMessage(`❌ Error: ${error.response.data.error}`);
      } else {
        setMessage('❌ Failed to create payroll. Please try again.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const taxAmount = (parseFloat(basicSalary || 0) + parseFloat(bonus || 0)) * (parseFloat(taxPercent || 0) / 100);
  const netSalary = (parseFloat(basicSalary || 0) + parseFloat(bonus || 0)) - parseFloat(deductions || 0) - taxAmount;

  return (
    <div className="payroll-container">
      <h1>Create Payroll</h1>
      
      {isLoading && <div className="loading-overlay">Processing...</div>}
      
      <form onSubmit={handleSubmit} className="payroll-form">
        <div className="form-group">
          <label>Employee *</label>
          <select 
            value={selectedEmployee} 
            onChange={(e) => setSelectedEmployee(e.target.value)} 
            className="form-control"
            required
            disabled={isLoading}
          >
            <option value="">Select Employee</option>
            {employees.map((employee) => (
              <option key={employee.id} value={employee.id}>
                {employee.name} ({employee.email})
              </option>
            ))}
          </select>
        </div>

        <div className="form-row">
          <div className="form-group">
            <label>Basic Salary (£) *</label>
            <input 
              type="number" 
              value={basicSalary} 
              onChange={(e) => setBasicSalary(e.target.value)} 
              className="form-control" 
              min="0"
              step="0.01"
              required
              disabled={isLoading}
            />
          </div>

          <div className="form-group">
            <label>Bonus (£)</label>
            <input 
              type="number" 
              value={bonus} 
              onChange={(e) => setBonus(e.target.value)} 
              className="form-control"
              min="0"
              step="0.01"
              disabled={isLoading}
            />
          </div>

          <div className="form-group">
            <label>Deductions (£)</label>
            <input 
              type="number" 
              value={deductions} 
              onChange={(e) => setDeductions(e.target.value)} 
              className="form-control"
              min="0"
              step="0.01"
              disabled={isLoading}
            />
          </div>

          <div className="form-group">
            <label>Tax (%)</label>
            <input 
              type="number" 
              value={taxPercent} 
              onChange={(e) => setTaxPercent(e.target.value)} 
              className="form-control"
              min="0"
              max="100"
              step="0.1"
              disabled={isLoading}
            />
          </div>
        </div>

        <div className="preview-box">
          <h3>Salary Preview</h3>
          <div className="preview-row">
            <span>Basic Salary:</span>
            <span>£{parseFloat(basicSalary || 0).toFixed(2)}</span>
          </div>
          <div className="preview-row">
            <span>Bonus:</span>
            <span>£{parseFloat(bonus || 0).toFixed(2)}</span>
          </div>
          <div className="preview-row">
            <span>Deductions:</span>
            <span>£{parseFloat(deductions || 0).toFixed(2)}</span>
          </div>
          <div className="preview-row">
            <span>Tax ({taxPercent || 0}%):</span>
            <span>£{taxAmount.toFixed(2)}</span>
          </div>
          <div className="preview-row total">
            <span>Net Salary:</span>
            <span>£{netSalary.toFixed(2)}</span>
          </div>
        </div>

        <button 
          type="submit" 
          className="submit-btn"
          disabled={isLoading}
        >
          {isLoading ? 'Processing...' : 'Create Payroll'}
        </button>
      </form>

      {message && (
        <div className={`message ${message.includes('✅') ? 'success' : 'error'}`}>
          {message}
        </div>
      )}
    </div>
  );
}

export default CreatePayroll;