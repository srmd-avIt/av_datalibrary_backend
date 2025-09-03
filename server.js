// src/server/index.js

const express = require('express');
const cors = require('cors');
const db = require('./db'); // This now imports the mysql2 pool
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// --- ENDPOINTS CONVERTED TO ASYNC/AWAIT ---

// This endpoint gets all records from the Events table
app.get('/api/users', async (req, res) => { // Added async
  try {
    const [results] = await db.query('SELECT * FROM Events');
    res.json(results);
  } catch (err) {
    console.error("Database query error on /api/users:", err);
    return res.status(500).json({ error: 'Database query failed' });
  }
});

// Endpoint for NewMediaLog table
app.get('/api/newmedialog', async (req, res) => { // Added async
  try {
    const [results] = await db.query('SELECT * FROM NewMediaLog');
    res.json(results);
  } catch (err) {
    console.error("Database query error on /api/newmedialog:", err);
    return res.status(500).json({ error: 'Database query failed' });
  }
});

// Endpoint for DigitalRecordings table
app.get('/api/digitalrecording', async (req, res) => { // Added async
  try {
    const [results] = await db.query('SELECT * FROM DigitalRecordings');
    res.json(results);
  } catch (err) {
    console.error("Database query error on /api/digitalrecording:", err);
    return res.status(500).json({ error: 'Database query failed' });
  }
});

// --- NEW ENDPOINTS FOR AUXFILES TABLE ---

// Endpoint to get all records from the AuxFiles table
app.get('/api/auxfiles', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM AuxFiles');
    res.json(results);
  } catch (err) {
    console.error("Database query error on /api/AuxFiles:", err);
    return res.status(500).json({ error: 'Database query failed' });
  }
});

// Endpoint to get a single auxiliary file by its code
app.get('/api/auxfiles/:fkMLID', async (req, res) => {
    const { fkMLID } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM AuxFiles WHERE fkMLID = ?', [fkMLID]);

        if (results.length === 0) {
            return res.status(404).json({ message: `Auxiliary file with code ${fkMLID} not found.` });
        }
        res.json(results[0]);
    } catch (err) {
        console.error("Database query error on single auxiliary file:", err);
        return res.status(500).json({ error: 'Database query failed' });
    }
});


// --- ENDPOINTS FOR SINGLE RECORDS ---

// Endpoint to get a single event by EventCode
app.get('/api/events/:eventCode', async (req, res) => { // Added async
    const { eventCode } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM Events WHERE EventCode = ?', [eventCode]);

        if (results.length === 0) {
            return res.status(404).json({ message: `Event with code ${eventCode} not found.` });
        }
        res.json(results[0]);
    } catch (err) {
        console.error("Database query error on single event:", err);
        return res.status(500).json({ error: 'Database query failed' });
    }
});

// Endpoint to get a single digital recording
app.get('/api/digitalrecording/:recordingCode', async (req, res) => { // Added async
    const { recordingCode } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM DigitalRecordings WHERE RecordingCode = ?', [recordingCode]);

        if (results.length === 0) {
            return res.status(404).json({ message: `Digital Recording with code ${recordingCode} not found.` });
        }
        res.json(results[0]);
    } catch (err) {
        console.error("Database query error on single digital recording:", err);
        return res.status(500).json({ error: 'Database query failed' });
    }
});

// --- NEW ENDPOINT FOR SINGLE NEW MEDIA LOG ---
app.get('/api/newmedialog/:mlid', async (req, res) => {
    // FIX: Use 'mlid' to match the route parameter name
    const { mlid } = req.params;
    try {
        // FIX: Use the 'mlid' variable in the query
        const [results] = await db.query('SELECT * FROM NewMediaLog WHERE MLUniqueID = ?', [mlid]);

        if (results.length === 0) {
            // FIX: Use 'mlid' in the error message for correct debugging
            return res.status(404).json({ message: `Media Log with ID ${mlid} not found.` });
        }
        res.json(results[0]);
    } catch (err) {
        console.error("Database query error on single media log:", err);
        return res.status(500).json({ error: 'Database query failed' });
    }
});


// Start server
const PORT = process.env.PORT || 3600;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});