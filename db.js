const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    user: process.env.POSTGRES_USER,
    password: process.env.POSTGRES_PASSWORD,
    database:process.env.POSTGRES_DATABASE,
    port: process.env.POSTGRES_PORT,
    host:process.env.POSTGRES_HOST
});

module.exports = {
    query:(text, params) => pool.query(text, params)
};