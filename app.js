'use strict';

const debug = require('debug')('auth-passport:app');
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const logger = require('morgan');
const wicked = require('wicked-sdk');
const passport = require('passport');

const session = require('express-session');
const FileStore = require('session-file-store')(session);

const google = require('./providers/google');
const github = require('./providers/github');
const twitter = require('./providers/twitter');
const facebook = require('./providers/facebook');
const oauth2 = require('./providers/oauth2');
const utils = require('./providers/utils');

// Use default options, see https://www.npmjs.com/package/session-file-store
const sessionStoreOptions = {};

const SECRET = 'ThisIsASecret';

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
        // TODO: This is not deal-breaking, as we're in a quite secure surrounding anyway,
        // but currently Kong sends 'X-Forwarded-Proto: http', which is plain wrong. And that
        // prevents the securing of the cookies. We know it's okay right now, so we do it
        // anyway - the Auth Server is SSL terminated at HAproxy, and the rest is http but
        // in the internal network of Docker.

        //sessionArgs.cookie.secure = true;
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
    const basePath = app.get('base_path');

    app.use(basePath + '/google', google);
    app.use(basePath + '/github', github);
    app.use(basePath + '/twitter', twitter);
    app.use(basePath + '/facebook', facebook);
    app.use(basePath + '/oauth2', oauth2);

    // CORS enable this end point
    app.get(basePath + '/profile', utils.cors(), function (req, res, next) {
        debug(basePath + '/profile');
        debug(req.session);

        if (!req.session ||
            !req.session.userValid ||
            !req.session.passport ||
            !req.session.passport.user)
            return res.status(400).json({ message: 'You need a valid session to call ' + basePath + '/profile.' });

        res.json(req.session.passport.user);
    });

    app.get(basePath + '/failure', function (req, res, next) {
        debug(basePath + '/failure');

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
