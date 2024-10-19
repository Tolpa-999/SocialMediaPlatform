const express = require('express');

const userRoute = express.Router();

const userController = require('../controller/usrers.controller');
const verifyToken = require('../middlewares/verifyToken');


userRoute.route('/')
    .get(verifyToken, userController.getAllUsers)

userRoute.route('/register')
    .post(userController.register)

userRoute.route('/verify-email')
    .post(userController.verifyEmail)

userRoute.route('/login')
    .post(userController.login)

// reset password
userRoute.route('/reset-pass-req')
    .post(verifyToken, userController.reset_password_request)
userRoute.route('/reset-pass')
    .post(verifyToken, userController.reset_password)

// settings
userRoute.route('/settings')
    .get(verifyToken, userController.get_settings)
    .post(verifyToken, userController.update_settings)

userRoute.route('/refresh')
    .post(userController.refresh)

userRoute.route('/header')
    .post(userController.header)

userRoute.route('/logout')
    .get(userController.logout)

module.exports = userRoute;