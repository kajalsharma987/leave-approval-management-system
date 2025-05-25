require('dotenv').config({ path: '../.env' }); // Load environment variables from parent directory
const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('./db'); // Your database connection

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

app.use(express.json()); // Middleware to parse JSON body
app.use(express.static(path.join(__dirname, '../public'))); // Serve static files from 'public' folder

// --- Middleware for Authentication and Authorization ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) return res.status(401).json({ message: 'Authentication token required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or expired token' });
        req.user = user; // user payload contains { id, name, email, role }
        next();
    });
};

const authorizeRoles = (roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Forbidden: You do not have the required role' });
        }
        next();
    };
};

// --- API Endpoints ---

// User Registration
app.post('/api/register', async (req, res) => {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password || !role) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    if (!['student', 'teacher', 'admin'].includes(role)) {
        return res.status(400).json({ message: 'Invalid role specified.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
            [name, email, hashedPassword, role],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed: users.email')) {
                        return res.status(409).json({ message: 'Email already registered.' });
                    }
                    console.error("Database error during registration:", err.message);
                    return res.status(500).json({ message: 'Server error during registration.' });
                }
                res.status(201).json({ message: 'User registered successfully!' });
            }
        );
    } catch (error) {
        console.error("Registration error:", error.message);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

// User Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) {
            console.error("Database error during login:", err.message);
            return res.status(500).json({ message: 'Server error.' });
        }
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { id: user.id, name: user.name, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '1h' } // Token expires in 1 hour
        );

        res.status(200).json({
            message: 'Login successful',
            token: token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    });
});

// Apply for Leave
app.post('/api/leaves', authenticateToken, async (req, res) => {
    const { leaveType, startDate, endDate, reason } = req.body;
    const { id: applicantId, name: applicantName, role: applicantRole } = req.user;

    if (!leaveType || !startDate || !endDate || !reason) {
        return res.status(400).json({ message: 'All leave fields are required.' });
    }
    if (new Date(startDate) > new Date(endDate)) {
        return res.status(400).json({ message: 'Start date cannot be after end date.' });
    }

    const submittedAt = new Date().toISOString(); // ISO 8601 format

    db.run(`INSERT INTO leave_applications (applicantId, applicantName, applicantRole, leaveType, startDate, endDate, reason, status, submittedAt)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [applicantId, applicantName, applicantRole, leaveType, startDate, endDate, reason, 'Pending', submittedAt],
        function(err) {
            if (err) {
                console.error("Database error submitting leave:", err.message);
                return res.status(500).json({ message: 'Failed to submit leave application.' });
            }
            res.status(201).json({ message: 'Leave application submitted successfully!', leaveId: this.lastID });
        }
    );
});

// Get User's Own Leaves
app.get('/api/leaves/my', authenticateToken, (req, res) => {
    const userId = req.user.id;
    db.all('SELECT * FROM leave_applications WHERE applicantId = ? ORDER BY submittedAt DESC', [userId], (err, leaves) => {
        if (err) {
            console.error("Database error fetching my leaves:", err.message);
            return res.status(500).json({ message: 'Failed to fetch your leave applications.' });
        }
        res.status(200).json(leaves);
    });
});

// Get Pending Approvals (for Teachers and Admins)
app.get('/api/leaves/pending', authenticateToken, authorizeRoles(['teacher', 'admin']), (req, res) => {
    const userRole = req.user.role;
    let query = 'SELECT * FROM leave_applications WHERE status = ?';
    let params = ['Pending'];

    if (userRole === 'teacher') {
        query += ' AND applicantRole = ?';
        params.push('student');
    }
    query += ' ORDER BY submittedAt ASC';

    db.all(query, params, (err, leaves) => {
        if (err) {
            console.error("Database error fetching pending leaves:", err.message);
            return res.status(500).json({ message: 'Failed to fetch pending leave applications.' });
        }
        res.status(200).json(leaves);
    });
});

// Approve/Reject Leave (for Teachers and Admins)
app.put('/api/leaves/:id/status', authenticateToken, authorizeRoles(['teacher', 'admin']), (req, res) => {
    const leaveId = req.params.id;
    const { status, approverRemarks } = req.body;
    const { id: approverId, name: approverName, role: approverRole } = req.user;
    const approvedAt = new Date().toISOString();

    if (!['Approved', 'Rejected'].includes(status)) {
        return res.status(400).json({ message: 'Invalid status provided.' });
    }

    db.get('SELECT * FROM leave_applications WHERE id = ?', [leaveId], (err, leave) => {
        if (err) {
            console.error("Database error fetching leave for update:", err.message);
            return res.status(500).json({ message: 'Server error.' });
        }
        if (!leave) {
            return res.status(404).json({ message: 'Leave application not found.' });
        }
        if (leave.status !== 'Pending') {
            return res.status(400).json({ message: 'Leave is not in Pending status.' });
        }

        // Authorization check specific to teacher role
        if (approverRole === 'teacher' && leave.applicantRole !== 'student') {
            return res.status(403).json({ message: 'Teachers can only approve/reject student leaves.' });
        }

        db.run(`UPDATE leave_applications SET
            status = ?,
            approverId = ?,
            approverName = ?,
            approvedAt = ?,
            approverRemarks = ?
            WHERE id = ?`,
            [status, approverId, approverName, approvedAt, approverRemarks, leaveId],
            function(err) {
                if (err) {
                    console.error("Database error updating leave status:", err.message);
                    return res.status(500).json({ message: 'Failed to update leave status.' });
                }
                if (this.changes === 0) {
                    return res.status(404).json({ message: 'Leave application not found or no changes made.' });
                }
                res.status(200).json({ message: `Leave ${status} successfully!` });
            }
        );
    });
});

// Catch-all to serve index.html for SPA routing
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../public', 'index.html'));
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});