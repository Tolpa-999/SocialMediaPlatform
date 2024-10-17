const jwt = require('jsonwebtoken')
module.exports = async (payload, time) => {
    const token = await jwt.sign(payload, process.env.
        JWT_SECRET_KEY, { expiresIn: `${time}` })
    return token;
}