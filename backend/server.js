require('dotenv').config();
const express = require('express');
const { Client } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 5000;


app.use(cors());
app.use(express.json());

const client = new Client({
  user: process.env.PGUSER,
  host: process.env.PGHOST,
  database: process.env.PGDATABASE,
  password: process.env.PGPASSWORD,
  port: process.env.PGPORT,
});

client.connect()
  .then(() => console.log('Database connected successfully'))
  .catch(err => {
    console.error('Database connection error', err);
    process.exit(1);
  });

// Health check endpoint
app.get('/', (req, res) => {
  res.send('Payroll Management System API is running');
});

// Database test endpoint
app.get('/test-db', async (req, res) => {
  try {
    const result = await client.query('SELECT NOW()');
    res.json({ dbTime: result.rows[0].now });
  } catch (error) {
    res.status(500).json({ error: 'Database connection error' });
  }
});


app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await client.query('SELECT * FROM admin WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const admin = result.rows[0];
    const match = await bcrypt.compare(password, admin.password);
    if (!match) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: admin.id, username: admin.username, role: 'admin' },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ 
      message: 'Login successful', 
      token,
      role: 'admin',
      user: {
        id: admin.id,
        username: admin.username
      }
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: "Error during login" });
  }
});

// Employee Login
app.post('/employee/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await client.query('SELECT * FROM employee WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const employee = result.rows[0];
    const match = await bcrypt.compare(password, employee.password);
    if (!match) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { 
        id: employee.id, 
        email: employee.email, 
        role: 'employee' 
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ 
      message: 'Login successful', 
      token,
      role: 'employee',
      employee: {
        id: employee.id,
        name: employee.name,
        email: employee.email,
        phone: employee.phone
      }
    });
  } catch (error) {
    console.error('Employee login error:', error);
    res.status(500).json({ error: "Error during login" });
  }
});

// Employee Signup
app.post('/employee/signup', async (req, res) => {
  const { name, email, password, phone } = req.body;

  try {
    
    const emailCheck = await client.query(
      'SELECT * FROM employee WHERE email = $1', 
      [email]
    );
    if (emailCheck.rows.length > 0) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    
    const hashedPassword = await bcrypt.hash(password, 10);

    
    const result = await client.query(
      `INSERT INTO employee (name, email, phone, password)
       VALUES ($1, $2, $3, $4)
       RETURNING id, name, email, phone`,
      [name, email, phone, hashedPassword]
    );

    res.status(201).json({ 
      message: 'Employee registered successfully',
      employee: result.rows[0]
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Error during registration' });
  }
});

app.get('/api/employees/count', verifyToken('admin'), async (req, res) => {
  try {
    
    const result = await client.query('SELECT COUNT(*) AS count FROM employee');
    
    res.json({ count: parseInt(result.rows[0].count, 10) });
  } catch (error) {
    console.error('Error fetching employee count:', error);
    res.status(500).json({ error: 'Failed to fetch employee count' });
  }
});

app.get('/employees', verifyToken('admin'), async (req, res) => {
  try {
    const result = await client.query(
      'SELECT id, name, email, phone FROM employee ORDER BY id'
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching employees:', error);
    res.status(500).json({ error: 'Failed to fetch employees' });
  }
});


app.post('/employees', verifyToken('admin'), async (req, res) => {
  const { name, email, phone, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await client.query(
      `INSERT INTO employee (name, email, phone, password)
       VALUES ($1, $2, $3, $4)
       RETURNING id, name, email, phone`,
      [name, email, phone, hashedPassword]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error adding employee:', error);
    res.status(500).json({ error: 'Failed to add employee' });
  }
});


app.put('/employees/:id', verifyToken('admin'), async (req, res) => {
  const { id } = req.params;
  const { name, email, phone } = req.body;

  try {
    const result = await client.query(
      `UPDATE employee 
       SET name = $1, email = $2, phone = $3
       WHERE id = $4
       RETURNING id, name, email, phone`,
      [name, email, phone, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Employee not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating employee:', error);
    res.status(500).json({ error: 'Failed to update employee' });
  }
});

app.delete('/api/employees/:id', async (req, res) => {
  const { id } = req.params;

  try {
    
    await client.query('DELETE FROM payroll WHERE employee_id = $1', [id]);

    
    await client.query('DELETE FROM employee WHERE id = $1', [id]);

    res.status(200).json({ message: 'Employee and related payroll records deleted successfully' });
  } catch (error) {
    console.error('Error deleting employee:', error);
    res.status(500).json({ error: 'Failed to delete employee' });
  }
});



// Process payroll (Admin only)
app.post('/payroll', verifyToken('admin'), async (req, res) => {
  const { employeeId, basicSalary, bonus = 0, deductions = 0, taxPercent = 0 } = req.body;

  try {
    
    const taxAmount = (basicSalary + bonus) * (taxPercent / 100);
    const netSalary = basicSalary + bonus - taxAmount - deductions;
    const paymentDate = new Date();

    const result = await client.query(
      `INSERT INTO payroll (employee_id, basic_salary, bonus, deductions, tax_percent, net_salary, payment_date)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [employeeId, basicSalary, bonus, deductions, taxPercent, netSalary, paymentDate]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error processing payroll:', error);
    res.status(500).json({ error: 'Failed to process payroll' });
  }
});

// Get payroll for employee
app.get('/payroll/:employeeId', verifyToken(), async (req, res) => {
  const { employeeId } = req.params;

  
  if (isNaN(employeeId) || parseInt(employeeId) <= 0) {
    return res.status(400).json({ error: 'Invalid employee ID' });
  }

  try {
    const result = await client.query(
      'SELECT * FROM payroll WHERE employee_id = $1 ORDER BY payment_date DESC',
      [employeeId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching payroll:', error);
    res.status(500).json({ error: 'Failed to fetch payroll' });
  }
});



// Submit leave request
app.post('/leaves', verifyToken('employee'), async (req, res) => {
  const { date, reason } = req.body;
  const employeeId = req.user.id;

  try {
    const result = await client.query(
      `INSERT INTO leave_requests (employee_id, date, reason, status)
       VALUES ($1, $2, $3, 'Pending')
       RETURNING *`,
      [employeeId, date, reason]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating leave request:', error);
    res.status(500).json({ error: 'Failed to create leave request' });
  }
});

app.get('/api/leave-requests/pending/count', verifyToken('admin'), async (req, res) => {
  try {
    const result = await client.query(
      'SELECT COUNT(*) FROM leave_requests WHERE status = $1',
      ['Pending']
    );
    res.json({ count: parseInt(result.rows[0].count) });
  } catch (error) {
    console.error('Error counting pending leaves:', error);
    res.status(500).json({ error: "Failed to count pending leaves" });
  }
});


app.get('/api/leave-requests/pending', verifyToken('admin'), async (req, res) => {
  try {
    const result = await client.query(
      `SELECT lr.*, e.name as employee_name, e.email as employee_email
       FROM leave_requests lr
       JOIN employee e ON lr.employee_id = e.id
       WHERE lr.status = 'Pending'
       ORDER BY lr.date DESC`
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: "Failed to fetch pending leave requests" });
  }
});

// Leave Request Endpoints
app.post('/leave-requests', verifyToken('employee'), async (req, res) => {
  try {
    const { date, reason } = req.body;
    const employeeId = req.user.id;

    
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ error: "Invalid date format. Use YYYY-MM-DD" });
    }

    const result = await client.query(
      `INSERT INTO leave_requests (employee_id, date, reason, status)
       VALUES ($1, $2, $3, 'Pending')
       RETURNING *`,
      [employeeId, date, reason]
    );

    res.status(201).json({
      message: 'Leave request submitted successfully',
      leaveRequest: result.rows[0]
    });
  } catch (error) {
    console.error('Leave request submission error:', error);
    res.status(500).json({ 
      error: "Failed to submit leave request",
      details: error.message 
    });
  }
});

// Get leave requests for employee
app.get('/leave-requests/employee', verifyToken('employee'), async (req, res) => {
  try {
    const result = await client.query(
      `SELECT lr.*, e.name as employee_name
       FROM leave_requests lr
       JOIN employee e ON lr.employee_id = e.id
       WHERE lr.employee_id = $1
       ORDER BY lr.date DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching leave requests:', error);
    res.status(500).json({ error: "Failed to fetch leave requests" });
  }
});

// Backend Route: Employee submits attendance
app.post('/employee/attendance', verifyToken('employee'), async (req, res) => {
  const { inTime, outTime } = req.body;
  const employeeId = req.user.id;

  try {
    
    console.log('Received inTime:', inTime, 'outTime:', outTime);

    
    const today = new Date().toISOString().split('T')[0];
    const existing = await client.query(
      `SELECT * FROM attendance 
       WHERE employee_id = $1 
       AND DATE(in_time) = $2`,
      [employeeId, today]
    );

    console.log('Existing attendance:', existing.rows);

    if (existing.rows.length > 0) {
      
      await client.query(
        `UPDATE attendance 
         SET in_time = $1, out_time = $2 
         WHERE employee_id = $3 AND DATE(in_time) = $4`,
        [inTime, outTime, employeeId, today]
      );
      return res.json({ message: 'Attendance updated successfully.' });
    }

    
    await client.query(
      `INSERT INTO attendance (employee_id, in_time, out_time)
       VALUES ($1, $2, $3)`,
      [employeeId, inTime, outTime]
    );

    res.json({ message: 'Attendance recorded successfully.' });
  } catch (error) {
    console.error('Error saving attendance:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.get('/admin/attendance', verifyToken('admin'), async (req, res) => {
  try {
    
    const result = await client.query(`
      SELECT a.employee_id, e.name as employee_name, a.in_time, a.out_time
      FROM attendance a
      JOIN employee e ON a.employee_id = e.id
      ORDER BY a.in_time DESC;
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching attendance:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Update leave status (Admin only)
app.put('/leaves/:id/status', verifyToken('admin'), async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  
  const validStatuses = ['Pending', 'Approved', 'Rejected'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ 
      error: 'Invalid status',
      validStatuses: validStatuses
    });
  }

  
  if (isNaN(Number(id))) {
    return res.status(400).json({ error: 'Invalid leave request ID' });
  }

  try {
    
    const checkResult = await client.query(
      'SELECT * FROM leave_requests WHERE id = $1',
      [id]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ 
        error: 'Leave request not found',
        details: `No leave request with ID ${id} exists`
      });
    }

    
    const result = await client.query(
      `UPDATE leave_requests 
       SET status = $1 
       WHERE id = $2
       RETURNING *`,
      [status, id]
    );

    
    const leaveWithEmployee = await client.query(
      `SELECT lr.*, e.name, e.email 
       FROM leave_requests lr
       JOIN employee e ON lr.employee_id = e.id
       WHERE lr.id = $1`,
      [id]
    );

    res.json({
      message: 'Leave status updated successfully',
      leaveRequest: result.rows[0],
      employee: {
        name: leaveWithEmployee.rows[0].name,
        email: leaveWithEmployee.rows[0].email
      }
    });

  } catch (error) {
    console.error('Error updating leave status:', {
      error: error.message,
      leaveId: id,
      timestamp: new Date().toISOString()
    });
    
    res.status(500).json({ 
      error: 'Failed to update leave status',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Authentication Middleware
function verifyToken(requiredRole) {
  return (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      if (requiredRole && decoded.role !== requiredRole) {
        return res.status(403).json({ error: 'Insufficient permissions' });
      }

      req.user = decoded;
      next();
    } catch (error) {
      console.error('Token verification failed:', error);
      res.status(401).json({ error: 'Invalid token' });
    }
  };
}

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});