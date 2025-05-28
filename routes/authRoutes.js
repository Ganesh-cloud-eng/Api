const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
 
const login = require('../controllers/authController');
const forget_password = require('../controllers/authController');
const reset_password = require('../controllers/authController');




router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.get('/me', authController.getUser);
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password/:token', authController.resetPassword);
router.route('/login').get(authController.login)   
router.route('/forget_password').get(authController.forget_password)
router.route('/reset_password').get(authController.reset_password)
module.exports = router;
