const jwt = require('jsonwebtoken');
require('dotenv').config();

function authenticate (req, res, next) {
    const authHeader = req.headers['authorization'];

    if(!authHeader){
        return res.status(401).json({error: "TOKEN_MISSING"});
    }

    const [scheme, token] = authHeader.split(' ');

    if(scheme !== 'Bearer' || !token){
        return res.status(401).json({error: "INVALID_TOKEN"});
    }
    try {
        const decoded = jwt.verify(token, process.env.ACCESS_SECRET_KEY);

        if(decoded.type !== 'access'){
            return res.status(401).json({error: "INVALID_TOKEN_TYPE"});
        }
        req.user = {
            userId: decoded.userId
        };
        
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: "TOKEN_EXPIRED" });
        }
        return res.status(401).json({ error: "INVALID_TOKEN" });
    }
}
module.exports = authenticate;