'use strict';

const debug = require('debug')('auth-google:app');
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const logger = require('morgan');
const wicked = require('wicked-sdk');
const passport = require('passport');

var session = require('express-session');
var FileStore = require('session-file-store')(session);

const google = require('./providers/google');
const github = require('./providers/github');
const twitter = require('./providers/twitter');
const facebook = require('./providers/facebook');

// Use default options, see https://www.npmjs.com/package/session-file-store
var sessionStoreOptions = {};

var SECRET = 'ThisIsASecret';

let sessionMinutes = 60;
if (process.env.AUTH_SERVER_SESSION_MINUTES) {
    console.log('Using session duration specified in env var AUTH_SERVER_SESSION_MINUTES.');
    sessionMinutes = Number(process.env.AUTH_SERVER_SESSION_MINUTES);
}
debug('Session duration: ' + sessionMinutes + ' minutes.');

// Specify the session arguments. Used for configuring the session component.
var sessionArgs = {
    store: new FileStore(sessionStoreOptions),
    secret: SECRET,
    saveUninitialized: true,
    resave: false,
    cookie: {
        maxAge: sessionMinutes * 60 * 1000
    }
};

const app = express();

app.initApp = function (callback) {

    if (!wicked.isDevelopmentMode()) {
        app.set('trust proxy', 1);
        sessionArgs.cookie.secure = true;
        console.log("Running in PRODUCTION MODE.");
    } else {
        console.log("=============================");
        console.log(" Running in DEVELOPMENT MODE");
        console.log("=============================");
        console.log("If you see this in your production logs, you're doing something wrong.");
    }

    app.use(wicked.correlationIdHandler());

    // view engine setup
    app.set('views', path.join(__dirname, 'views'));
    app.set('view engine', 'jade');

    logger.token('correlation-id', function (req, res) {
        return req.correlationId;
    });
    app.use(logger('{"date":":date[clf]","method":":method","url":":url","remote-addr":":remote-addr","version":":http-version","status":":status","content-length":":res[content-length]","referrer":":referrer","response-time":":response-time","correlation-id":":correlation-id"}'));

    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({ extended: false }));

    // Set up the cookie parser
    app.use(cookieParser(SECRET));
    // And session management
    app.use(session(sessionArgs));
    // Initialize Passport
    app.use(passport.initialize());
    app.use(passport.session());

    // =======================
    // Actual implementation
    // =======================

    app.use('/auth-server/google', google);
    app.use('/auth-server/github', github);
    app.use('/auth-server/twitter', twitter);
    app.use('/auth-server/facebook', facebook);

    app.get('/auth-server/profile', function (req, res, next) {
        debug('/auth-server/profile');

        if (!req.session ||
            !req.session.userValid ||
            !req.session.passport ||
            !req.session.passport.user)
            return res.status(400).json({ message: 'You need a valid session to call /profile.' });

        res.json(req.session.passport.user);
    });

    app.get('/auth-server/failure', function (req, res, next) {
        debug('/auth-server/failure');

        let redirectUri = null;
        if (req.session && req.session.redirectUri)
            redirectUri = req.session.redirectUri;

        res.render('failure', {
            title: 'Failure',
            correlationId: req.correlationId,
            returnUrl: redirectUri
        });
    });

    // =======================

    // catch 404 and forward to error handler
    app.use(function (req, res, next) {
        const err = new Error('Not Found');
        err.status = 404;
        next(err);
    });

    // production error handler
    // no stacktraces leaked to user
    app.use(function (err, req, res, next) {
        if (err.status !== 404) {
            console.error(err);
            console.error(err.stack);
        }
        res.status(err.status || 500);
        res.render('error', {
            title: 'Error',
            correlationId: req.correlationId,
            message: err.message,
            status: err.status
        });
    });

    callback(null);
};

module.exports = app;
