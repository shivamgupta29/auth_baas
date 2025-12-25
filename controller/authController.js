require('dotenv').config();
const db = require('../db.js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const SALT_ROUNDS = 11; 

async function RegisterUser (req, res){
    const { email, password } = req.body;
    const projectId = req.project.id;
    if(!projectId){
        return res.status(403).json({error: "FORBIDDEN"});
    }
    
    if(!email || !password || password.length < 8){
        return res.status(400).json({error: "INVALID_DATA"});
    }

    const normalizedEmail = email.toLowerCase().trim();
    try {
        const result = await db.query("SELECT id FROM users WHERE email = $1 and project_id=$2", [normalizedEmail, projectId]);
        if(result.rows.length > 0){
            return res.status(409).json({error: "EMAIL_ALREADY_EXISTS"});
        }

        const passwordhash = await bcrypt.hash(password, SALT_ROUNDS);

        await db.query("INSERT INTO users (email, password_hashed, project_id) VALUES ($1, $2, $3)", [normalizedEmail, passwordhash, projectId]);

        return res.status(201).json({message : "USER_REGISTERED"});

    } catch (e) {
        console.error(e);
        return res.status(500).json({error: "INTERNAL_SERVER_ERROR"});
    }
}

async function LoginUser (req, res) {
    const { email, password } = req.body;

    const projectId = req.project.id;
    if(!projectId){
        return res.status(403).json({error: "FORBIDDEN"});
    }

    if(!email || !password){
        return res.status(400).json({error: "INVALID_DATA"});
    }

    const normalizedEmail = email.toLowerCase().trim();

    try {
        const result = await db.query("SELECT id, password_hashed FROM users WHERE email=$1 and project_id=$2", [normalizedEmail, projectId]);
        
        if(result.rows.length === 0){
            return res.status(401).json({error: "INVALID_CREDENTIALS"});
        }

        const userId = result.rows[0].id;
        const passwordHash = result.rows[0].password_hashed;

        const isMatch = await bcrypt.compare(password, passwordHash);

        if(!isMatch){
            return res.status(401).json({error: "INVALID_CREDENTIALS"});
        }
        
        const accessToken = jwt.sign({userId, projectId,type:"access"}, process.env.ACCESS_SECRET_KEY, {expiresIn : '15m'});
        const refreshToken = jwt.sign({userId, projectId, type:"refresh"}, process.env.REFRESH_SECRET_KEY, {expiresIn : '7d'});

        const refreshHashed = await bcrypt.hash(refreshToken, SALT_ROUNDS);

        await db.query("UPDATE users SET refresh_token_hashed = $1 WHERE id=$2", [refreshHashed, userId]);

        return res.status(200).json({"accessToken": accessToken, "refreshToken": refreshToken});
    } catch (e) {
        console.error(e);
        return res.status(500).json({error: "INTERNAL_SERVER_ERROR"});
    }
}

async function RefreshAccessToken (req, res) {
    const incomingRefreshToken = req.body.refreshToken;
    if(!incomingRefreshToken){
        return res.status(401).json({error: "UNAUTHORISED_ACCESS"});
    }

    const projectId = req.project.id;
    if(!projectId){
        return res.status(403).json({error: "FORBIDDEN"});
    }

    try {
        const decoded = jwt.verify(incomingRefreshToken, process.env.REFRESH_SECRET_KEY);

        if(decoded.type !== 'refresh'){
            return res.status(401).json({error: "UNAUTHORISED_ACCESS"});
        }
        const userId = decoded.userId;
        const projectIdFromToken = decoded.projectId;
        
        if(projectIdFromToken !== projectId){
            return res.status(403).json({error: "FORBIDDEN"});
        }

        const result = await db.query("SELECT refresh_token_hashed, project_id FROM users WHERE id=$1", [userId]);
        if(result.rows.length === 0){
            return res.status(401).json({error: "UNAUTHORISED_ACCESS"});
        }

        const userProjectId = result.rows[0].project_id;
        if(userProjectId !== projectId){
            return res.status(403).json({error: "FORBIDDEN"});
        }

        const storedRefreshToken = result.rows[0].refresh_token_hashed;
        if(storedRefreshToken === null){
            return res.status(401).json({error: "UNAUTHORISED_ACCESS"});
        }

        const isValidToken = await bcrypt.compare(incomingRefreshToken,storedRefreshToken);

        if(!isValidToken){
            await db.query("UPDATE users SET refresh_token_hashed = $1 WHERE id=$2",[null, userId]);
            return res.status(401).json({error: "UNAUTHORISED_ACCESS"});
        }

        const accessToken = jwt.sign({userId, projectId, type:"access"}, process.env.ACCESS_SECRET_KEY, {expiresIn : '15m'});
        const refreshToken = jwt.sign({userId, projectId, type:"refresh"}, process.env.REFRESH_SECRET_KEY, {expiresIn : '7d'});  
        const hashedRefresh = await bcrypt.hash(refreshToken, SALT_ROUNDS);

        await db.query("UPDATE users SET refresh_token_hashed = $1 WHERE id=$2", [hashedRefresh, userId]);

        res.status(200).json({message: "TOKEN_GENERATED", "accessToken": accessToken, "refreshToken": refreshToken})

    } catch (err) {
        return res.status(401).json({error: "UNAUTHORISED_ACCESS"})
    }
}

async function LogoutUser(req, res) {
    try {
        const userId = req.user.userId;
    
        await db.query("UPDATE users SET refresh_token_hashed = $1 WHERE id=$2",[null, userId]);
    
        return res.status(200).json({message: "LOGOUT_SUCCESS"});
    } catch (e) {
        return res.status(200).json({message: "LOGOUT_SUCCESS"});
    }
}

module.exports ={
    RegisterUser,
    LoginUser,
    LogoutUser,
    RefreshAccessToken
}