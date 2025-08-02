import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import './payrollDetails.css';

function PayrollDetails() {
  const { state } = useLocation();
  const navigate = useNavigate();

  if (!state?.payroll) {
    return (
      <div className="payroll-container">
        <h2>No Payroll Data Found</h2>
        <p>Please create a payroll first to view details.</p>
        <button 
          className="submit-btn"
          onClick={() => navigate('/create-payroll')}
        >
          Back to Create Payroll
        </button>
      </div>
    );
  }

  const payroll = {
    ...state.payroll,
    basic_salary: Number(state.payroll.basic_salary),
    bonus: Number(state.payroll.bonus),
    deductions: Number(state.payroll.deductions),
    tax_percent: Number(state.payroll.tax_percent),
    net_salary: Number(state.payroll.net_salary)
  };

  const { employee, calculatedValues } = state;
  const paymentDate = new Date(payroll.payment_date).toLocaleDateString();

  return (
    <div className="payroll-container">
      <h1>Payroll Details</h1>
      
      <div className="details-card">
        <h2>{employee.name}</h2>
        <p>Email: {employee.email}</p>
        <p>Payment Date: {paymentDate}</p>
        
        <div className="preview-box">
          <h3>Salary Breakdown</h3>
          <div className="preview-row">
            <span>Basic Salary:</span>
            <span>£{payroll.basic_salary.toFixed(2)}</span>
          </div>
          <div className="preview-row">
            <span>Bonus:</span>
            <span>£{payroll.bonus.toFixed(2)}</span>
          </div>
          <div className="preview-row">
            <span>Deductions:</span>
            <span>£{payroll.deductions.toFixed(2)}</span>
          </div>
          <div className="preview-row">
            <span>Tax ({payroll.tax_percent.toFixed(1)}%):</span>
            <span>£{calculatedValues.taxAmount.toFixed(2)}</span>
          </div>
          <div className="preview-row total">
            <span>Net Salary:</span>
            <span>£{calculatedValues.netSalary.toFixed(2)}</span>
          </div>
        </div>

        <div className="action-buttons">
          <button 
            className="submit-btn"
            onClick={() => navigate('/admin/dashboard')}
          >
            Back to Dashboard
          </button>
        </div>
      </div>
    </div>
  );
}

export default PayrollDetails;