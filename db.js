const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Connect to SQLite database
// It will create 'leave_app.db' file in the root directory if it doesn't exist
const dbPath = path.resolve(__dirname, '../leave_app.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error connecting to database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        // Create tables if they don't exist
        db.serialize(() => {
            // Users table
            db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('student', 'teacher', 'admin'))
            )`, (err) => {
                if (err) console.error("Error creating users table:", err.message);
                else console.log("Users table ensured.");
            });

            // Leave applications table
            db.run(`CREATE TABLE IF NOT EXISTS leave_applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                applicantId INTEGER NOT NULL,
                applicantName TEXT NOT NULL,
                applicantRole TEXT NOT NULL,
                leaveType TEXT NOT NULL,
                startDate TEXT NOT NULL,
                endDate TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('Pending', 'Approved', 'Rejected')),
                submittedAt TEXT NOT NULL,
                approverId INTEGER,
                approverName TEXT,
                approvedAt TEXT,
                approverRemarks TEXT,
                FOREIGN KEY (applicantId) REFERENCES users(id)
            )`, (err) => {
                if (err) console.error("Error creating leave_applications table:", err.message);
                else console.log("Leave applications table ensured.");
            });

            // Optional: Insert a default admin user if none exists
            db.get("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'", (err, row) => {
                if (err) {
                    console.error("Error checking for admin user:", err.message);
                    return;
                }
                if (row.count === 0) {
                    const bcrypt = require('bcryptjs');
                    const adminPassword = bcrypt.hashSync('admin123', 10); // Change this to a secure password
                    db.run(`INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)`,
                        ['Admin User', 'admin@example.com', adminPassword, 'admin'],
                        function(err) {
                            if (err) console.error("Error inserting default admin:", err.message);
                            else console.log("Default admin user created: admin@example.com / admin123");
                        }
                    );
                }
            });
        });
    }
});

module.exports = db;