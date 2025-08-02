import React from 'react';
import EmployeeNav from './EmployeeNav';
import './EmployeeDashboard.css';

function EmployeeDashboard() {
  
  const employeeName = localStorage.getItem('employeeName') || 'Team Member';
  
  
  const currentHour = new Date().getHours();
  const greeting = currentHour < 12 ? 'Good Morning' : 
                  currentHour < 18 ? 'Good Afternoon' : 
                  'Good Evening';

                  return (
                    <div className="employee-layout">
                      <EmployeeNav />
                      <main className="employee-content">
                        <div className="content-wrapper">
                          
                          <div className="greeting-section">
                            <div className="greeting-content">
                              <h1 className="greeting-time">{greeting},</h1>
                              <p className="welcome-message">Welcome to your payroll portal</p>
                            </div>
                          </div>
                
                          
                          <div className="dashboard-empty-state">
                            <small>Want to see your payroll details? Click "My Payroll" in the sidebar</small>
                          </div>
                        </div>
                      </main>
                    </div>
                  );
                }

export default EmployeeDashboard;