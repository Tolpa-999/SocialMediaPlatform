const asyncWrapper = require("../middlewares/asyncWrapper")
const Users = require("../models/users.model")
const appError = require("../utils/appError")
const httpStatus = require("../utils/httpStatusText")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const generateJWT = require("../utils/generateJWT")

const getAllUsers = asyncWrapper(async (req, res, next) => {
    const users = await Users.find({}, { "__v": true, "password": true }).sort({ createdAt: -1 })

    console.table(users);

    res.status(200).json({
        status: httpStatus.SUCESS,
        data: users,
    })
})

const register = asyncWrapper(async (req, res, next) => {


    const { username, email, password } = req.body

    if (!username || !email || !password) {
        const error = appError.create("username, email, password are required", 400, httpStatus.FAIL)
        return next(error)
    }

    const oldUser = await Users.findOne({ username })

    if (oldUser) {
        const error = appError.create("user already exist", 400, httpStatus.FAIL)
        return next(error)
    }

    const bcryptPass = await bcrypt.hash(password, 9)

    const newUser = new Users({
        username,
        email,
        password: bcryptPass
    })

    const token = await generateJWT({ _id: newUser._id, username, email }, '1d')

    newUser.token = token

    await newUser.save()

    res.status(201).json({
        status: httpStatus.SUCESS,
        data: newUser,
    })
})

const login = asyncWrapper(async (req, res, next) => {
    const { email, password } = req.body

    if (!email || !password) {
        const error = appError.create("email and password are required", 401, httpStatus.FAIL)
        return next(error)
    }

    const user = await Users.findOne({ email: email }).select('+password');

    if (!user) {
        const error = appError.create("user not found", 400, httpStatus.FAIL)
        return next(error)
    }

    console.log(`before error `);
    const isMatch = await bcrypt.compare(password, user.password)
    console.log(`After error `);
    if (!isMatch) {
        const err = appError.create("invalid password or email", 400, httpStatus.FAIL);
        return next(err)
    }

    const accessToken = await generateJWT({ id: user._id, email: user.email, username: user.username }, '15m')


    // refresh token
    const refershToken = await generateJWT({ id: user._id, email: user.email, username: user.username }, '1d')

    res.cookie('refreshToken', refershToken, {
        httpOnly: true,
        secure: true,
        maxAge: 24 * 60 * 60 * 1000,
    })

    console.log(accessToken);

    return res.status(200).json({ status: httpStatus.SUCESS, data: { accessToken, user } })
})

const refresh = asyncWrapper(async (req, res, next) => {
    const oldToken = req.cookies?.refreshToken;

    if (!oldToken) {
        const error = appError.create("refresh token is required", 400, httpStatus.FAIL)
        return next(error)
    }

    jwt.verify(oldToken, process.env.JWT_SECRET_KEY, async (err, decoded) => {
        if (err) {
            // invalid token
            const err = appError.create("unavlid or expired token sign in again", 406, httpStatus.FAIL);
            return next(err)
        }



        // token is valid send new access token
        const accessToken = await generateJWT({ id: decoded._id, email: decoded.email, role: decoded.role }, '15m')

        const user = await Users.findOne({ email: decoded.email });

        console.log(accessToken);

        return res.status(200).json({
            status: httpStatus.SUCESS,
            data: {
                accessToken: accessToken,
                user,
            }
        })
    })

})

const header = asyncWrapper(async (req, res, next) => {

    const authHeader = req.headers['Authorization'] || req.headers['authorization']

    if (!authHeader) {
        const err = appError.create("no access token found in headers", 401, httpStatus.FAIL);
        return next(err)
    }

    const token = authHeader.split(' ')[1];


    jwt.verify(token, process.env.JWT_SECRET_KEY, async (err, decoded) => {
        if (err) {
            // invalid token
            const err = appError.create("unavlid or expired access token", 401, httpStatus.FAIL);
            return next(err)
        }



        // token is valid send new access token
        const accessToken = await generateJWT({ id: decoded._id, email: decoded.email, username: decoded.username }, '15m')

        const user = await Users.findOne({ email: decoded.email });

        // console.log(accessToken);

        return res.status(200).json({
            status: httpStatus.SUCESS,
            data: {
                user,
                accessToken
            }
        })
    })
})

const logout = asyncWrapper(async (req, res, next) => {
    // const oldToken = req.cookies?.refreshToken;
    await res.clearCookie('refreshToken')

    return res.status(200).json({
        status: httpStatus.SUCESS,
        data: null
    })

})

module.exports = {
    getAllUsers,
    register,
    login,
    refresh,
    header,
    logout
}
