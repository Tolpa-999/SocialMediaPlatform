const asyncWrapper = require("../middlewares/asyncWrapper")
const Users = require("../models/users.model")
const appError = require("../utils/appError")
const httpStatus = require("../utils/httpStatusText")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const generateJWT = require("../utils/generateJWT")
const { sendVerificationMail } = require("../services/verificationMail")
const crypto = require('crypto'); // To generate a random token

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

    // const token = await generateJWT({ _id: newUser._id, username, email }, '1h')

    // newUser.token = token

    const verificationToken = await jwt.sign({ _id: newUser._id, email }, process.env.EMAIL_SECRET, { expiresIn: '1h' })

    try {
        await sendVerificationMail(newUser.email, "Email Verification", `http://localhost:2002/api/users/verify-email?token=${verificationToken}`)
    } catch (error) {
        console.log(error);
    }

    await newUser.save()

    res.status(201).json({
        status: httpStatus.SUCESS,
        data: newUser,
    })
})

const verifyEmail = asyncWrapper(async (req, res, next) => {
    const token = req.query.token
    console.log(token);

    if (!token) {
        const error = appError.create("token is required", 400, httpStatus.FAIL)
        return next(error)
    }
    // const accessToken = await generateJWT({ token }, '1h')

    jwt.verify(token, process.env.EMAIL_SECRET, async (err, decoded) => {
        if (err) {
            const error = appError.create("invalid token", 400, httpStatus.FAIL)
            return next(error)
        }

        const user = await Users.findOne({ email: decoded.email });
        if (!user) {
            const error = appError.create("user not found", 400, httpStatus.FAIL)
            return next(error)
        }

        if (user.emailVerified) {
            const error = appError.create("user already verified", 400, httpStatus.FAIL)
            return next(error)
        }

        user.emailVerified = true
        await user.save()

        return res.status(200).json({ status: httpStatus.SUCESS, data: user })
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

    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) {
        const err = appError.create("invalid password or email", 400, httpStatus.FAIL);
        return next(err)
    }

    if (!user.emailVerified) {
        const err = appError.create("please verify your email", 400, httpStatus.FAIL);
        return next(err)
    }

    const accessToken = await generateJWT({ id: user._id, email: user.email, username: user.username }, '5h')


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

const reset_password_request = asyncWrapper(async (req, res, next) => {
    const { email } = req.body
    console.log(email);
    if (!email) {
        const error = appError.create("email is required to reset password", 404, httpStatus.FAIL)
        return next(error)
    }

    const user = await Users.findOne({ email: email })
    if (!user) {
        const error = appError.create("user not found", 404, httpStatus.FAIL)
        return next(error)
    }

    const token = await crypto.randomBytes(32).toString('hex');

    user.resetPasswordToken = `reset-${token}`
    user.resetPasswordExpires = Date.now() + 3600000 // 1 hour to expired
    await user.save()

    const url = `${req.protocol}://${req.get('host')}/api/users/reset_password?token=reset-${token}`

    await sendVerificationMail(email, 'Password Reset', url)

    return res.status(200).json({ status: httpStatus.SUCESS, data: user })
})

const reset_password = asyncWrapper(async (req, res, next) => {
    const { token } = req.query
    const { newPassword } = req.body
    console.log("token => ", token, "newPassword => ", newPassword);

    if (!token || !newPassword) {
        const error = appError.create("token and new password are required", 400, httpStatus.FAIL)
        return next(error)
    }




    const user = await Users.findOne({
        resetPasswordToken: token,
        // resetPasswordExpires: { $gt: Date.now() }
    }).select('+password');


    if (!user) {
        const error = appError.create("user not found", 400, httpStatus.FAIL)
        return next(error)
    }

    console.log(`before Erorr`);
    const isMatch = await bcrypt.compare(newPassword, user.password)
    if (isMatch) {
        const error = appError.create("new password cannot be the same as old password", 400, httpStatus.FAIL)
        return next(error)
    }
    console.log(`After Erorr`);

    const bcryptPass = await bcrypt.hash(newPassword, 9)

    // const user = await Users.findOneAndUpdate({
    //     resetPasswordToken: token,
    //     resetPasswordExpires: { $gt: Date.now() }
    // }, {
    //     password: bcryptPass,
    //     resetPasswordToken: null,
    //     resetPasswordExpires: null
    // })

    user.password = bcryptPass
    user.resetPasswordToken = null
    user.resetPasswordExpires = null
    await user.save()

    return res.status(200).json({ status: httpStatus.SUCESS, data: user })
})

const get_settings = asyncWrapper(async (req, res, next) => {
    const userName = req.body.username

    if (!userName) {
        const error = appError.create("username is required", 400, httpStatus.FAIL)
        return next(error)
    }

    const user = await Users.findOne({ username: userName }).select('name bio profilePicture')

    if (!user) {
        const error = appError.create("user not found", 400, httpStatus.FAIL)
        return next(error)
    }

    return res.status(200).json({ status: httpStatus.SUCESS, data: user })
})

const update_settings = asyncWrapper(async (req, res, next) => {
    const userName = req.body.username

    if (!userName) {
        const error = appError.create("username is required", 400, httpStatus.FAIL)
        return next(error)
    }

    const user = await Users.findOne({ username: userName }).select('name bio profilePicture')

    if (!user) {
        const error = appError.create("user not found", 400, httpStatus.FAIL)
        return next(error)
    }

    const { name, bio, profilePicture } = req.body

    user.name = name || '',
        user.bio = bio || '',
        user.profilePicture = profilePicture || 'defaultProfilePicture.jpg'


    await user.save()

    return res.status(200).json({ status: httpStatus.SUCESS, data: user })


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
    logout,
    verifyEmail,
    reset_password_request,
    reset_password,
    get_settings,
    update_settings,
}
