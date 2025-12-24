const express = require('express');
const { RegisterUser, LoginUser, refreshAccessToken, LogoutUser } = require('./controller/authController');
const authenticate = require('./middleware/authMiddleware');

const router = express.Router();

router.post('/login', LoginUser);
router.post('/register',RegisterUser);
router.post("/refresh", refreshAccessToken);
router.post("/logout", authenticate, LogoutUser);


module.exports = router;