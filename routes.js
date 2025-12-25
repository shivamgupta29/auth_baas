const express = require('express');
const { RegisterUser, LoginUser, RefreshAccessToken, LogoutUser } = require('./controller/authController');
const authenticate = require('./middleware/authMiddleware');
const apiAuthenticate = require('./middleware/projectMiddleware');

const router = express.Router();

router.post('/login', apiAuthenticate, LoginUser);
router.post('/register', apiAuthenticate, RegisterUser);
router.post("/refresh", apiAuthenticate, RefreshAccessToken);
router.post("/logout", apiAuthenticate, authenticate, LogoutUser);


module.exports = router;