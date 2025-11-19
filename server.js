// server.js
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const db = require('./db');
const { authRequired, requireRole } = require('./authMiddleware');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());
app.use(cors());

const PORT = process.env.PORT || 3000;

function createToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role, full_name: user.full_name },
    process.env.JWT_SECRET,
    { expiresIn: '8h' }
  );
}

// ---------------------- Routes ----------------------

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// 1. Register patient or doctor
app.post('/api/register', async (req, res) => {
  const { email, password, full_name, role, specialization } = req.body;

  if (!email || !password || !full_name || !role) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  if (!['PATIENT', 'DOCTOR'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }

  try {
    const password_hash = await bcrypt.hash(password, 10);

    // Check existing user
    const [existing] = await db.execute('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Email already used' });
    }

    const [result] = await db.execute(
      'INSERT INTO users (email, password_hash, full_name, role) VALUES (?, ?, ?, ?)',
      [email, password_hash, full_name, role]
    );

    const userId = result.insertId;

    if (role === 'PATIENT') {
      await db.execute('INSERT INTO patients (user_id) VALUES (?)', [userId]);
    } else if (role === 'DOCTOR') {
      await db.execute(
        'INSERT INTO doctors (user_id, specialization) VALUES (?, ?)',
        [userId, specialization || null]
      );
    }

    const user = { id: userId, email, full_name, role };
    const token = createToken(user);
    res.json({ token, user });
  } catch (err) {
    console.error('Error in /api/register', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 2. Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = rows[0];

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const cleanUser = {
      id: user.id,
      email: user.email,
      full_name: user.full_name,
      role: user.role
    };
    const token = createToken(cleanUser);
    res.json({ token, user: cleanUser });
  } catch (err) {
    console.error('Error in /api/login', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 3. Get list of doctors (for patient booking UI)
app.get('/api/doctors', authRequired, async (req, res) => {
  try {
    const [rows] = await db.execute(`
      SELECT d.id AS doctor_id, u.full_name, d.specialization
      FROM doctors d
      JOIN users u ON d.user_id = u.id
    `);
    res.json(rows);
  } catch (err) {
    console.error('Error in /api/doctors', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 4. Patient books appointment with doctor
app.post(
  '/api/appointments',
  authRequired,
  requireRole('PATIENT'),
  async (req, res) => {
    const { doctor_id, appointment_time } = req.body;
    if (!doctor_id || !appointment_time) {
      return res.status(400).json({ error: 'Missing doctor_id or appointment_time' });
    }

    try {
      const [patientRows] = await db.execute(
        'SELECT id FROM patients WHERE user_id = ?',
        [req.user.id]
      );
      if (patientRows.length === 0) {
        return res.status(400).json({ error: 'Patient profile not found' });
      }
      const patient = patientRows[0];

      const [result] = await db.execute(
        `INSERT INTO appointments (patient_id, doctor_id, appointment_time)
         VALUES (?, ?, ?)`,
        [patient.id, doctor_id, appointment_time]
      );

      const apptId = result.insertId;
      const [apptRows] = await db.execute(
        'SELECT id, appointment_time, status FROM appointments WHERE id = ?',
        [apptId]
      );
      res.json(apptRows[0]);
    } catch (err) {
      console.error('Error in /api/appointments', err);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// 5. Doctor views their appointments
app.get(
  '/api/doctor/appointments',
  authRequired,
  requireRole('DOCTOR'),
  async (req, res) => {
    try {
      const [docRows] = await db.execute(
        'SELECT id FROM doctors WHERE user_id = ?',
        [req.user.id]
      );
      if (docRows.length === 0) {
        return res.status(400).json({ error: 'Doctor profile not found' });
      }
      const doctor = docRows[0];

      const [appointments] = await db.execute(
        `
        SELECT a.id,
               a.appointment_time,
               a.status,
               u.full_name AS patient_name
        FROM appointments a
        JOIN patients p ON a.patient_id = p.id
        JOIN users u ON p.user_id = u.id
        WHERE a.doctor_id = ?
        ORDER BY a.appointment_time
      `,
        [doctor.id]
      );

      res.json(appointments);
    } catch (err) {
      console.error('Error in /api/doctor/appointments', err);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// ----------------------------------------------------

app.listen(PORT, () => {
  console.log(`Backend running on port ${PORT}`);
});
