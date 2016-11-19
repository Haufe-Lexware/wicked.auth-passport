'use strict';

const google = require('express').Router();
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const debug = require('debug')('auth-passport:google');
const wicked = require('wicked-sdk');

const utils = require('./utils');

google.authenticateSettings = {
    failureRedirect: '/auth-server/failure'
};

google.init = function (app, authConfig) {
    debug('init()');
    google.authServerName = app.get('server_name');
    google.basePath = app.get('base_path');
    if (!authConfig.google) {
        debug('Not configuring google authentication.');
        return;
    }

    google.authenticateSettings.failureRedirect = google.basePath + '/failure';

    if (!authConfig.google.clientId)
        throw new Error('In auth-server configuration, property "google", the property "clientId" is missing.');
    if (!authConfig.google.clientSecret)
        throw new Error('In auth-server configuration, property "google", the property "clientSecret" is missing.');
    if (!authConfig.google.callbackUrl)
        throw new Error('In auth-server configuration, property "google", the property "callbackUrl" is missing.');

    // Configure passport
    passport.use(new GoogleStrategy({
        clientID: authConfig.google.clientId,
        clientSecret: authConfig.google.clientSecret,
        callbackURL: authConfig.google.callbackUrl
    }, function (accessToken, refreshToken, profile, done) {
        debug('Google Authentication succeeded.');
        // We'll always accept Google Identities, no matter what.
        normalizeProfile(profile, function (err, userProfile) {
            if (err) {
                debug('normalizeProfile failed.');
                console.error(err);
                console.error(err.stack);
                return done(err);
            }
            debug('Google normalized user profile:');
            debug(userProfile);
            done(null, userProfile);
        });
    }));

    const authenticateWithGoogle = passport.authenticate('google', { scope: ['profile', 'email'] });
    const authenticateCallback = passport.authenticate('google', google.authenticateSettings);

    google.get('/api/:apiId', utils.verifyClientAndAuthenticate('google', authenticateWithGoogle));
    google.get('/callback', authenticateCallback, utils.authorizeAndRedirect('google', google.authServerName));

    debug('Configured google authentication.');
};

function normalizeProfile(profile, callback) {
    const email = getEmail(profile);
    const email_verified = !!email;
    const userProfile = {
        id: 'google:' + profile.id,
        sub: 'google:' + profile.id,
        username: utils.makeUsername(profile.displayName, profile.username),
        preferred_username: utils.makeUsername(profile.displayName, profile.username),
        name: profile.displayName,
        given_name: profile.name.givenName,
        family_name: profile.name.familyName,
        email: email,
        email_verified: email_verified,
        raw_profile: profile,
    };
    callback(null, userProfile);
}

function getEmail(profile) {
    debug('getEmail()');
    if (!profile.emails)
        return null;
    if (profile.emails.length <= 0)
        return null;
    return profile.emails[0].value;
}

module.exports = google;
