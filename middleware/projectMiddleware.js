const db = require("../db");

async function apiAuthenticate (req, res, next) {
    const key = req.headers['x-api-key'];
    if(!key){
        return res.status(403).json({error: "FORBIDDEN"});
    }
    try {
        const result = await db.query("SELECT id FROM projects WHERE public_key = $1", [key]);
        if(result.rows.length === 0){
            return res.status(403).json({error: "FORBIDDEN"});
        }
        const projectId = result.rows[0].id;

        req.project = {id: projectId};
        next();
    } catch (e) {
        return res.status(403).json({error: "FORBIDDEN"})
    }
    
}
module.exports = apiAuthenticate;