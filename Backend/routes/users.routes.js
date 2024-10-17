const express = require('express');

const userRoute = express.Router();

const userController = require('../controller/usrers.controller');
const verifyToken = require('../middlewares/verifyToken');


userRoute.route('/')
    .get(verifyToken, userController.getAllUsers)

userRoute.route('/register')
    .post(userController.register)

userRoute.route('/login')
    .post(userController.login)

userRoute.route('/refresh')
    .post(userController.refresh)

userRoute.route('/header')
    .post(userController.header)

userRoute.route('/logout')
    .get(userController.logout)

module.exports = userRoute;