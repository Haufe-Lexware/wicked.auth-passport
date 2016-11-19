'use strict';

const debug = require('debug')('auth-passport:facebook');
const passport = require('passport');
const FacebookStrategy = require('passport-facebook');
const request = require('request');

const utils = require('./utils');

const facebook = require('express').Router();

// Will be overridden as soon as the base path is known
facebook.authenticateSettings = {
    failureRedirect: '/auth-server/failure'
};

facebook.init = function (app, authConfig) {
    debug('init()');
    facebook.authServerName = app.get('server_name');
    facebook.basePath = app.get('base_path');

    if (!authConfig.facebook) {
        debug('Not configuring facebook authentication');
        return;
    }

    facebook.authenticateSettings.failureRedirect = facebook.basePath + '/failure';

    passport.use('facebook', new FacebookStrategy({
        clientID: authConfig.facebook.clientId,
        clientSecret: authConfig.facebook.clientSecret,
        callbackURL: authConfig.facebook.callbackUrl
    }, function (accessToken, refreshToken, profile, done) {
        debug('Facebook authentication succeeded.');
        debug('Access token: ' + accessToken);
        normalizeProfile(profile, accessToken, function (err, userProfile) {
            if (err) {
                debug('normalizeProfile failed.');
                console.error(err);
                console.error(err.stack);
                return done(err);
            }
            debug('Facebook normalized user profile:');
            debug(userProfile);
            done(null, userProfile);
        });
    }));

    const authenticateWithFacebook = passport.authenticate('facebook', { scope: ['public_profile', 'email'] });
    const authenticateCallback = passport.authenticate('facebook', facebook.authenticateSettings);

    facebook.get('/api/:apiId', utils.verifyClientAndAuthenticate('facebook', authenticateWithFacebook));
    facebook.get('/callback', authenticateCallback, utils.authorizeAndRedirect('facebook', facebook.authServerName));

    debug('Configured facebook authentication.');
};

function normalizeProfile(profile, accessToken, callback) {
    debug('normalizeProfile()');

    // Using the FB Graph API is quite cool actually.
    request.get({
        url: 'https://graph.facebook.com/v2.8/me?fields=id,name,first_name,last_name,email',
        headers: {
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + accessToken
        }
    }, function (err, res, body) {
        if (err)
            return callback(err);
        if (res.statusCode !== 200) {
            console.error('Unexpected status code from Facebook: ' + res.statusCode);
            console.error(body);
            return callback(utils.makeError('Could not retrieve user profile from Facebook. Status Code: ' + res.statusCode));
        }
        const jsonBody = utils.getJson(body);
        debug('User profile:');
        debug(jsonBody);

        const email = jsonBody.email;
        const email_verified = !!email;

        const userProfile = {
            id: 'facebook:' + jsonBody.id,
            username: jsonBody.name,
            preferred_username: jsonBody.name,
            name: jsonBody.name,
            given_name: jsonBody.first_name,
            family_name: jsonBody.last_name,
            email: email,
            email_verified: email_verified,
            raw_profile: profile
        };

        return callback(null, userProfile);
    });
}

module.exports = facebook;
