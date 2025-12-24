const express = require('express')
require('dotenv').config();

const authRoutes = require('./routes');

const app = express();
const PORT = 3000;

app.use(express.json());

app.use('/api/auth', authRoutes);

app.listen(PORT)
