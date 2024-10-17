const jwt = require('jsonwebtoken')

const verifyToken = (req, res, next) => {
    const authHeader = req.headers['Authorization'] || req.headers['authorization']

    if (!authHeader) {
        return res.status(403).send({ auth: false, message: 'No token provided' })
    }

    const token = authHeader.split(' ')[1]

    jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(401).send({ err: err.message, message: 'invalid token' })
        }
        req.userId = decoded.id
        next()
    })
}

module.exports = verifyToken