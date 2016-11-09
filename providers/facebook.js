'use strict';

const debug = require('debug')('auth-passport:facebook');
const passport = require('passport');
const FacebookStrategy = require('passport-facebook');
const request = require('request');

const utils = require('./utils');

const facebook = require('express').Router();

facebook.init = function (authConfig, authServerName) {
    debug('init()');
    facebook.authServerName = authServerName;

    if (!authConfig.facebook) {
        debug('Not configuring facebook authentication');
        return;
    }

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

    debug('Configured facebook authentication.');
};

const authenticateWithFacebook = passport.authenticate('facebook', { scope: ['public_profile', 'email'] });
const authenticateCallback = passport.authenticate('facebook', { failureRedurect: '/auth-server/failure' });

facebook.get('/api/:apiId', utils.verifyClientAndAuthenticate('facebook', authenticateWithFacebook));
facebook.get('/callback', authenticateCallback, utils.authorizeAndRedirect('facebook', facebook.authServerName));

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
            full_name: jsonBody.name,
            first_name: jsonBody.first_name,
            last_name: jsonBody.last_name,
            email: email,
            email_verified: email_verified,
            raw_profile: profile
        };

        return callback(null, userProfile);
    });
}

module.exports = facebook;
