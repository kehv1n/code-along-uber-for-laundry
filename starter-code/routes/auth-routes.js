const express = require('express');
const authRoutes = express.Router();
const bcrypt = require('bcrypt');
const User = require('../models/user');
const passport = require('passport');
const connectFlash = require('connect-flash');

const bcryptSalt = 10;

authRoutes.get('/signup', (req, res, next) => {
    res.render('auth/signup.ejs', {
        errorMessage: '',
        title: 'Signup'
    });
});

authRoutes.post('/signup', (req, res, next) => {
    const nameInput = req.body.name;
    const emailInput = req.body.email;
    const passwordInput = req.body.password;

    if (emailInput === '' || passwordInput === '') {
        res.render('auth/signup', {
            errorMessage: 'Enter both email and password to sign up.'
        });
        return;
    }

    User.findOne({
        email: emailInput
    }, '_id', (err, existingUser) => {
        if (err) {
            next(err);
            return;
        }

        if (existingUser !== null) {
            res.render('auth/signup', {
                errorMessage: `The email ${emailInput} is already in use.`
            });
            return;
        }

        const salt = bcrypt.genSaltSync(bcryptSalt);
        const hashedPass = bcrypt.hashSync(passwordInput, salt);

        const userSubmission = {
            name: nameInput,
            email: emailInput,
            password: hashedPass
        };

        const theUser = new User(userSubmission);

        theUser.save((err) => {
            if (err) {
                res.render('auth/signup', {
                    errorMessage: 'Something went wrong. Try again later.'
                });
                return;
            }

            res.redirect('/');
        });
    });
});

authRoutes.get('/login', (req, res, next) => {
  res.render('auth/login.ejs', {
    errorMessage: req.flash('message')
  });
});

authRoutes.post('/login',
  passport.authenticate('local', {
    successReturnToOrRedirect : '/', //Saves the previous location of the user
    failureRedirect : '/login', //IF they try to go to a non-authenticated page
    failureFlash : true, // Sends them there once they are authenticated
    successFlash : 'You have been logged in, user!',
  })
);






module.exports = authRoutes;
