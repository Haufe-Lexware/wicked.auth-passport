'use strict';

const debug = require('debug')('auth-passport:twitter');
const passport = require('passport');
const request = require('request');
const TwitterStrategy = require('passport-twitter');

const utils = require('./utils');

const twitter = require('express').Router();

twitter.authenticateSettings = {
    failureRedirect: '/auth-server/failure'
};

twitter.init = function (app, authConfig) {
    debug('init()');
    twitter.authServerName = app.get('server_name');
    twitter.basePath = app.get('base_path');
    if (!authConfig.twitter) {
        debug('Not configuring twitter authentication.');
        return;
    }

    twitter.authenticateSettings.failureRedirect = twitter.basePath + '/failure';

    if (!authConfig.twitter.consumerKey)
        throw new Error('In auth-server configuration, property "twitter", the property "consumerKey" is missing.');
    if (!authConfig.twitter.consumerSecret)
        throw new Error('In auth-server configuration, property "twitter", the property "consumerSecret" is missing.');
    if (!authConfig.twitter.callbackUrl)
        throw new Error('In auth-server configuration, property "twitter", the property "callbackUrl" is missing.');

    passport.use(new TwitterStrategy({
        consumerKey: authConfig.twitter.consumerKey,
        consumerSecret: authConfig.twitter.consumerSecret,
        callbackURL: authConfig.twitter.callbackUrl
    }, function (accessToken, refreshToken, profile, done) {
        debug('Twitter Authentication succeeded.');
        normalizeProfile(profile, accessToken, function (err, userProfile) {
            if (err) {
                debug('normalizeProfile failed.');
                console.error(err);
                console.error(err.stack);
                return done(err);
            }
            debug('Twitter normalized user profile:');
            debug(userProfile);
            done(null, userProfile);
        });
    }));

    const authenticateWithTwitter = passport.authenticate('twitter');
    const authenticateCallback = passport.authenticate('twitter', twitter.authenticateSettings);

    twitter.get('/api/:apiId', utils.verifyClientAndAuthenticate('twitter', authenticateWithTwitter));
    twitter.get('/callback', authenticateCallback, utils.authorizeAndRedirect('twitter', twitter.authServerName));

    debug('Configured twitter authentication.');
};

function normalizeProfile(profile, accessToken, callback) {
    debug('normalizeProfile()');

    const nameGuess = utils.splitName(profile.displayName, profile.username);
    const email = null; // We don't get email addresses from Twitter as a default
    const email_verified = false;

    const userProfile = {
        id: 'twitter:' + profile.id,
        sub: 'twitter:' + profile.id,
        username: utils.makeUsername(nameGuess.fullName, profile.username),
        preferred_username: utils.makeUsername(nameGuess.fullName, profile.username),
        name: nameGuess.fullName,
        given_name: nameGuess.firstName,
        family_name: nameGuess.lastName,
        email: email,
        email_verified: email_verified,
        raw_profile: profile
    };

    /*
    // This requires special permissions to get email addresses; otherwise you just
    // get a strange error message back, after ten to twenty seconds.
    request.get({
        url: 'https://api.twitter.com/1.1/account/verify_credentials.json?include_email=true',
        headers: {
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + accessToken
        }, function (err, res, body) {
            if (err)
                return callback(err);
            const jsonBody = utils.getJson(body);

            // This is not tested, and might be wrong; the docs on this at Twitter are really
            // bad:
            if (jsonBody.email) {
                // If we have an email address, Twitter assures it's already verified.
                userProfile.email = jsonBody.email;
                userProfile.email_verified = true;
            }

            callback(null, userProfile);
        }
    });
    */

    // In case the above code is commented _in_, this has to be commented _out_:
    callback(null, userProfile);
}

module.exports = twitter;
