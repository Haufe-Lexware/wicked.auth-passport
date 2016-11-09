'use strict';

const debug = require('debug')('auth-passport:twitter');
const passport = require('passport');
const request = require('request');
const TwitterStrategy = require('passport-twitter');

const utils = require('./utils');

const twitter = require('express').Router();

twitter.init = function (authConfig, authServerName) {
    debug('init()');
    twitter.authServerName = authServerName;
    if (!authConfig.twitter) {
        debug('Not configuring twitter authentication.');
        return;
    }

    if (!authConfig.twitter.consumerKey)
        throw new Error('In auth-server configuration, property "twitter", the property "consumerKey" is missing.');
    if (!authConfig.twitter.consumerSecret)
        throw new Error('In auth-server configuration, property "twitter", the property "consumerSecret" is missing.');
    if (!authConfig.twitter.callbackUrl)
        throw new Error('In auth-server configuration, property "google", the property "callbackUrl" is missing.');

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

    debug('Configured twitter authentication.');
};

const authenticateWithTwitter = passport.authenticate('twitter');
const authenticateCallback = passport.authenticate('twitter', { failureRedirect: '/auth-server/failure' });

twitter.get('/api/:apiId', utils.verifyClientAndAuthenticate('twitter', authenticateWithTwitter));
twitter.get('/callback', authenticateCallback, utils.authorizeAndRedirect('twitter', twitter.authServerName));

function normalizeProfile(profile, accessToken, callback) {
    debug('normalizeProfile()');

    const nameGuess = utils.splitName(profile.displayName, profile.username);
    const email = null; // We don't get email addresses from Twitter as a default
    const email_verified = false;

    const userProfile = {
        id: 'twitter:' + profile.id,
        full_name: nameGuess.fullName,
        first_name: nameGuess.firstName,
        last_name: nameGuess.lastName,
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
