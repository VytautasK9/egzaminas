const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { inspect } = require('util');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// MySQL Connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'myapp'
});

db.connect(err => {
    if (err) {
        console.error('Error connecting to MySQL:', err.message);
        process.exit(1);
    }
    console.log('MySQL connected...');
});

// Verify Token Middleware for regular users
function verifyToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).send({ auth: false, message: 'No token provided.' });

    jwt.verify(token.split(' ')[1], 'supersecret', (err, decoded) => {
        if (err) return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });
        req.userId = decoded.id;
        next();
    });
}

// Verify Admin Token Middleware
function verifyAdminToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).send({ auth: false, message: 'No token provided.' });

    jwt.verify(token.split(' ')[1], 'supersecret', (err, decoded) => {
        if (err) return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });
        if (!decoded.isAdmin) return res.status(403).send({ auth: false, message: 'Not authorized as admin.' });
        req.adminId = decoded.id;
        next();
    });
}

// Register User Endpoint
app.post('/api/register', (req, res) => {
    const { username, password, role } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);

    const sql = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
    db.query(sql, [username, hashedPassword, role], (err, result) => {
        if (err) {
            console.error('Error inserting user:', err.message);
            return res.status(500).send('Server error');
        }
        res.status(200).send('User registered');
    });
});

// Login User Endpoint
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    const sql = 'SELECT * FROM users WHERE username = ?';
    db.query(sql, [username], (err, results) => {
        if (err) {
            console.error('Error selecting user:', err.message);
            return res.status(500).send('Server error');
        }
        if (results.length === 0) return res.status(404).send('User not found');

        const user = results[0];
        const passwordIsValid = bcrypt.compareSync(password, user.password);

        if (!passwordIsValid) return res.status(401).send('Invalid password');

        const token = jwt.sign({ id: user.id, role: user.role }, 'supersecret', { expiresIn: 86400 });
        res.status(200).send({ auth: true, token });
    });
});

// Register Admin Endpoint
app.post('/api/admin/register', (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);

    const sql = 'INSERT INTO administrators (username, password) VALUES (?, ?)';
    db.query(sql, [username, hashedPassword], (err, result) => {
        if (err) {
            console.error('Error inserting admin:', err.message);
            return res.status(500).send('Server error');
        }
        res.status(200).send('Admin registered');
    });
});

// Login Admin Endpoint
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;

    const sql = 'SELECT * FROM administrators WHERE username = ?';
    db.query(sql, [username], (err, results) => {
        if (err) {
            console.error('Error selecting admin:', err.message);
            return res.status(500).send('Server error');
        }
        if (results.length === 0) return res.status(404).send('Admin not found');

        const admin = results[0];
        const passwordIsValid = bcrypt.compareSync(password, admin.password);

        if (!passwordIsValid) return res.status(401).send('Invalid password');

        const token = jwt.sign({ id: admin.id, isAdmin: true }, 'supersecret', { expiresIn: 86400 });
        res.status(200).send({ auth: true, token });
    });
});

// Add Event Endpoint
app.post('/api/events', verifyToken, (req, res) => {
    const { name, date, description } = req.body;
    const sql = 'INSERT INTO events (name, date, description, status) VALUES (?, ?, ?, ?)';
    db.query(sql, [name, date, description, 'pending'], (err, result) => {
        if (err) {
            console.error('Error inserting event:', err.message);
            console.error('Request body:', inspect(req.body));
            return res.status(500).send('Server error');
        }
        res.status(200).send('Event added');
    });
});

// Get Events Endpoint
app.get('/api/events', (req, res) => {
    const sql = 'SELECT * FROM events';
    db.query(sql, (err, results) => {
        if (err) {
            console.error('Error selecting events:', err.message);
            return res.status(500).send('Server error');
        }
        res.status(200).send(results);
    });
});

// Get Pending Events Endpoint
app.get('/api/events/pending', verifyToken, (req, res) => {
    const sql = 'SELECT * FROM events WHERE status = ?';
    db.query(sql, ['pending'], (err, results) => {
        if (err) {
            console.error('Error selecting pending events:', err.message);
            return res.status(500).send('Server error');
        }
        res.status(200).send(results);
    });
});

// Approve Event Endpoint
app.put('/api/events/approve/:eventId', verifyAdminToken, (req, res) => {
    const { eventId } = req.params;
    const sql = 'UPDATE events SET status = ? WHERE id = ?';
    db.query(sql, ['approved', eventId], (err, result) => {
        if (err) {
            console.error('Error updating event status:', err.message);
            return res.status(500).send('Server error');
        }
        res.status(200).send('Event approved');
    });
});

// Reject Event Endpoint
app.put('/api/events/reject/:eventId', verifyAdminToken, (req, res) => {
    const { eventId } = req.params;
    const sql = 'UPDATE events SET status = ? WHERE id = ?';
    db.query(sql, ['rejected', eventId], (err, result) => {
        if (err) {
            console.error('Error updating event status:', err.message);
            return res.status(500).send('Server error');
        }
        res.status(200).send('Event rejected');
    });
});

// Delete Event Endpoint
app.delete('/api/events/:eventId', verifyAdminToken, (req, res) => {
    const { eventId } = req.params;
    const sql = 'DELETE FROM events WHERE id = ?';
    db.query(sql, [eventId], (err, result) => {
        if (err) {
            console.error('Error deleting event:', err.message);
            return res.status(500).send('Server error');
        }
        res.status(200).send('Event deleted');
    });
});

// Add Rating Endpoint
app.post('/api/events/rate/:eventId', verifyToken, (req, res) => {
    const { eventId } = req.params;
    const { rating } = req.body;
    
    const sql = 'UPDATE events SET rating = ? WHERE id = ?';
    db.query(sql, [rating, eventId], (err, result) => {
        if (err) {
            console.error('Error updating event rating:', err.message);
            return res.status(500).send('Server error');
        }
        res.status(200).send('Event rated');
    });
});
// Rate Event Endpoint
app.post('/api/events/rate/:eventId', verifyToken, (req, res) => {
    const { eventId } = req.params;
    const { rating } = req.body;

    const sqlSelect = 'SELECT rating, total_ratings FROM events WHERE id = ?';
    const sqlUpdate = 'UPDATE events SET rating = ?, total_ratings = ? WHERE id = ?';

    db.query(sqlSelect, [eventId], (err, results) => {
        if (err) {
            console.error('Error selecting event:', err.message);
            return res.status(500).send('Server error');
        }
        if (results.length === 0) {
            return res.status(404).send('Event not found');
        }

        const currentRating = results[0].rating;
        const totalRatings = results[0].total_ratings;

        const newRating = ((currentRating * totalRatings) + rating) / (totalRatings + 1);
        const newTotalRatings = totalRatings + 1;

        db.query(sqlUpdate, [newRating, newTotalRatings, eventId], (err, result) => {
            if (err) {
                console.error('Error updating event rating:', err.message);
                return res.status(500).send('Server error');
            }
            res.status(200).send({ newRating, newTotalRatings });
        });
    });
});

// Get Categories Endpoint
app.get('/api/categories', (req, res) => {
    const sql = 'SELECT * FROM categories';
    db.query(sql, (err, results) => {
        if (err) {
            console.error('Error selecting categories:', err.message);
            return res.status(500).send('Server error');
        }
        res.status(200).send(results);
    });
});

const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
