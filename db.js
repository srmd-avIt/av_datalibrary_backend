// db.js

const mysql = require('mysql2/promise');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT, // <-- add this line
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 30000
});

console.log(`✅ Database connection pool configured for ${process.env.DB_HOST}:${process.env.DB_PORT}`);

module.exports = pool;