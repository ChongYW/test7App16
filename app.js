var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
const passport = require('passport');
const session = require('express-session');
const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const connectFlash = require('connect-flash');
const expressFlash = require('express-flash');

var app = express();

// MongoDB Connection : 
mongoose.connect('mongodb://localhost:27017/test7App16');
// MongoDB Connection . 

// Define User Schema : 
const User = require('./models/user'); // Create this model
// Define User Schema . 

// view engine setup : 
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
// view engine setup . 

// Middleware : 
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(connectFlash()); // Use connect-flash middleware
app.use(expressFlash());

app.use(session({ secret: 'your-secret-key', resave: true, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use((req, res, next) => {
  res.locals.errorMessage = req.flash('error'); // Make flash messages available in templates
  next();
});

// Middleware to check if user is authenticated
const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    res.locals.errorMessage = req.flash('error'); // Make flash error messages available in templates
    res.locals.successMessage = req.flash('success'); // Make flash success messages available in templates
    return next(); // User is authenticated, proceed to the next middleware/route
  }
  req.flash('error', 'You must be logged in to access this page.');
  res.redirect('/login'); // User is not authenticated, redirect to the login page
};

// Add a new middleware to check if the user is not authenticated
const ensureNotAuthenticated = (req, res, next) => {
  if (!req.isAuthenticated()) {
    return next(); // User is not authenticated, proceed to the next middleware/route
  }
  res.redirect('/'); // User is authenticated, redirect to the home page
};
// Middleware . 

// Passport Configuration : 
passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
// Passport Configuration .

// Routes : 
// app.use('/', indexRouter);
// app.use('/users', usersRouter);

// Show "Dashboard" or ask user to login
app.get('/', (req, res) => {
  res.render('index.ejs', { user: req.user });
});

// Show login form
app.get('/login', ensureNotAuthenticated, (req, res) => {
  res.render('login.ejs');
});

// Start seting up the authentication
app.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true,
  })
);

// Logout function
app.get('/logout', function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

// Show register form
app.get('/register', ensureNotAuthenticated, (req, res) => {
  res.render('register.ejs');
});

// Register function
app.post('/register', (req, res) => {
  // Create a new user
  User.register(new User({ username: req.body.username }), req.body.password, (err, user) => {
    if (err) {
      console.error(err);
      return res.render('register.ejs'); // Render registration form again on error
    }
    // Log in the user after successful registration
    passport.authenticate('local')(req, res, () => {
      res.redirect('/');
    });
  });
});

// Show password change form
app.get('/change-password', ensureAuthenticated, (req, res) => {
  res.render('change-password.ejs');
});

// Password change function
app.post('/change-password', ensureAuthenticated, (req, res) => {
  let isValid = true;

  const { oldPassword, newPassword, confirmPassword } = req.body;

  // Check if new password and confirm password match
  if (newPassword !== confirmPassword) {
    isValid = false;
    req.flash('error', 'New password and confirm password do not match.');
    // return res.redirect('/change-password');
  }

  // Use the `changePassword` method provided by passport-local-mongoose
  req.user.changePassword(oldPassword, newPassword, (err) => {
    if (err) {
      isValid = false;
      req.flash('error', 'Failed to change password. Please check your old password.');
      // return res.redirect('/change-password');
    }
    
    if (isValid) {
      req.flash('success', 'Password changed successfully.');
      res.redirect('/');
    }else{
      return res.render('change-password');
    }
    
  });
});

// app.listen(3000, () => {
//   console.log('Server started on port 3000');
// });

// Routes .

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
