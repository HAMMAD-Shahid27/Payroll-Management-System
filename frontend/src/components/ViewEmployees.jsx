import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './ViewEmployees.css';

const EmployeeManagement = () => {
  const [employees, setEmployees] = useState([]);
  const [editingEmployee, setEditingEmployee] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    phone: '',
    password: '',
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchEmployees();
    resetFormData();
  }, []);

  const fetchEmployees = async () => {
    try {
      const response = await axios.get('http://localhost:5000/employees', {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
      });
      setEmployees(response.data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching employees:', error);
    }
  };

  const resetFormData = () => {
    setFormData({ name: '', email: '', phone: '', password: '' });
  };

  const handleFormChange = (e) => {
    const { name, value } = e.target;
    setFormData((prevData) => ({
      ...prevData,
      [name]: value,
    }));
  };

  const handleAddEmployee = async () => {
    try {
      const response = await axios.post(
        'http://localhost:5000/employees',
        formData,
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem('token')}`,
          },
        }
      );
      setEmployees([...employees, response.data]);
      resetFormData();
    } catch (error) {
      console.error('Error adding employee:', error);
    }
  };

  // Update employee
  const handleUpdateEmployee = async (id) => {
    try {
      const response = await axios.put(
        `http://localhost:5000/employees/${id}`,
        formData,
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem('token')}`,
          },
        }
      );
      const updatedEmployees = employees.map((employee) =>
        employee.id === id ? response.data : employee
      );
      setEmployees(updatedEmployees);
      setEditingEmployee(null);
      resetFormData();
    } catch (error) {
      console.error('Error updating employee:', error);
    }
  };

  const handleDeleteEmployee = async (id) => {
    try {
      await axios.delete(`http://localhost:5000/api/employees/${id}`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
      });
      setEmployees(employees.filter((employee) => employee.id !== id));
    } catch (error) {
      console.error('Error deleting employee:', error);
    }
  };

  
  const handleEditClick = (employee) => {
    setEditingEmployee(employee);
    setFormData({
      name: employee.name,
      email: employee.email,
      phone: employee.phone,
      password: '',
    });
  };

  return (
    <div className="employee-management-container">
      <h2>Employee Management</h2>

      {/* Add/Edit Employee Form */}
      <div className="employee-form">
        <h3>{editingEmployee ? 'Edit Employee' : 'Add New Employee'}</h3>
        <input
          type="text"
          name="name"
          value={formData.name}
          onChange={handleFormChange}
          placeholder="Name"
        />
        <input
          type="email"
          name="email"
          value={formData.email}
          onChange={handleFormChange}
          placeholder="Email"
        />
        <input
          type="text"
          name="phone"
          value={formData.phone}
          onChange={handleFormChange}
          placeholder="Phone"
        />
        <input
          type="password"
          name="password"
          value={formData.password}
          onChange={handleFormChange}
          placeholder="Password"
        />
        {editingEmployee ? (
          <button
            className="update-button"
            onClick={() => handleUpdateEmployee(editingEmployee.id)}
          >
            Update Employee
          </button>
        ) : (
          <button className="add-button" onClick={handleAddEmployee}>
            Add Employee
          </button>
        )}
      </div>

      {/* Employee List */}
      <div className="employee-list">
        <h3>Employee List</h3>
        {loading ? (
          <p>Loading...</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Phone</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {employees.map((employee) => (
                <tr key={employee.id}>
                  <td>{employee.name}</td>
                  <td>{employee.email}</td>
                  <td>{employee.phone}</td>
                  <td>
                    <button
                      className="edit-button"
                      onClick={() => handleEditClick(employee)}
                    >
                      Edit
                    </button>
                    <button
                      className="delete-button"
                      onClick={() => handleDeleteEmployee(employee.id)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default EmployeeManagement;
