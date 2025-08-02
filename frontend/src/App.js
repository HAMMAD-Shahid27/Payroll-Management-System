// App.js
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import 'bootstrap/dist/css/bootstrap.min.css';
import Login from './components/Login';
import Signup from './components/signup';
import EmployeeDashboard from './components/EmployeeDashboard';
import CreatePayroll from './components/CreatePayroll';
import AdminDashboard from './components/AdminDashboard';
import EmployeePayroll from './components/EmployeePayroll';
import LoginLand from './components/loginlanding';
import PayrollDetails from './components/payrollDetails';
import ViewEmployees from './components/ViewEmployees';
import AdminLeaves from './components/AdminLeave';
import LeaveRequest from './components/EmployeeLeave';
import  MyLeaves from './components/MyLeaves';
import EmployeeAttendance from './components/EmployeeAttendance';
import AdminAttendance from './components/AdminAttendance'

function App() {
  return (
    <Routes>
      <Route path="/" element={<LoginLand />} />
      <Route path="/login/admin" element={<Login isAdmin={true} />} />
      <Route path="/login/employee" element={<Login isAdmin={false} />} />
      <Route path="/signup" element={<Signup />} />
      <Route path="/payroll-details" element={<PayrollDetails />} />
      <Route path="/admin/attendance" element={<AdminAttendance />} />
      <Route path="/employee/attendance" element={<EmployeeAttendance />} />
      <Route path="/employee/leave-request" element={<LeaveRequest />} />
      <Route path="/employee/my-leaves" element={<MyLeaves />} />
      <Route path="/admin/leaves" element={<AdminLeaves />} />
      <Route path="/admin/dashboard" element={<AdminDashboard />} />
      <Route path="/employee" element={<EmployeeDashboard />} />
      <Route path="/employee/my-payroll" element={<EmployeePayroll />} />
      <Route path="/admin/payroll" element={<CreatePayroll />} />
      <Route path="/admin/employees" element={<ViewEmployees />} />
      <Route path="/employee/my-payroll" element={<EmployeePayroll />} />
    </Routes>
  );
}

export default App;