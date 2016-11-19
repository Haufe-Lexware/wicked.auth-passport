'use strict';

const request = require('request');
const passport = require('passport');
const GithubStrategy = require('passport-github2');
const wicked = require('wicked-sdk');
const debug = require('debug')('auth-passport:github');

const utils = require('./utils');

const github = require('express').Router();

github.authenticateSettings = {
    failureRedirect: '/auth-server/failure'
};

github.init = function (app, authConfig) {
    debug('init()');
    github.authServerName = app.get('server_name');
    github.basePath = app.get('base_path');
    if (!authConfig.github) {
        debug('Not configuring github authentication.');
        return;
    }

    github.authenticateSettings.failureRedirect = github.basePath + '/failure'; 

    if (!authConfig.github.clientId)
        throw new Error('In auth-server configuration, property "google", the property "clientId" is missing.');
    if (!authConfig.github.clientSecret)
        throw new Error('In auth-server configuration, property "google", the property "clientSecret" is missing.');
    if (!authConfig.github.callbackUrl)
        throw new Error('In auth-server configuration, property "google", the property "callbackUrl" is missing.');

    passport.use(new GithubStrategy({
        clientID: authConfig.github.clientId,
        clientSecret: authConfig.github.clientSecret,
        callbackURL: authConfig.github.callbackUrl
    }, function (accessToken, refreshToken, profile, done) {
        debug('Github Authenticate succeeded.');
        normalizeProfile(profile, accessToken, function (err, userProfile) {
            debug('callback normalizeProfile()');
            if (err) {
                debug('But normalizeProfile failed.');
                console.error(err);
                console.error(err.stack);
                return done(err);
            }
            debug('Normalized Profile:');
            debug(userProfile);
            done(null, userProfile);
        });
    }));

    const authenticateWithGithub = passport.authenticate('github', { scope: ['user:email'] });
    const authenticateCallback = passport.authenticate('github', github.authenticateSettings);

    github.get('/api/:apiId', utils.verifyClientAndAuthenticate('github', authenticateWithGithub));
    github.get('/callback', authenticateCallback, utils.authorizeAndRedirect('github', github.authServerName));

    debug('Configured github authentication.');
};

function normalizeProfile(profile, accessToken, callback) {
    debug('normalizeProfile()');
    // Get the email addresses; they are not included in the OAuth profile directly.
    request.get({
        url: 'https://api.github.com/user/emails',
        headers: {
            'User-Agent': 'wicked API Portal',
            'Authorization': 'Bearer ' + accessToken,
            'Accept': 'application/json'
        }
    }, function (err, apiResponse, apiBody) {
        if (err)
            return callback(err);
        debug('Github Email retrieved.');

        const nameGuess = utils.splitName(profile.displayName, profile.username);
        const email = getEmailData(utils.getJson(apiBody));

        const userProfile = {
            id: 'github:' + profile.id,
            sub: 'github:' + profile.id,
            username: utils.makeUsername(nameGuess.fullName, profile.username),
            preferred_username: utils.makeUsername(nameGuess.fullName, profile.username),
            name: nameGuess.fullName,
            given_name: nameGuess.firstName,
            family_name: nameGuess.lastName,
            email: email.email,
            email_verified: email.verified,
            raw_profile: profile,
        };

        return callback(null, userProfile);
    });
}

function getEmailData(emailResponse) {
    debug('getEmailData()');
    var email = {
        email: null,
        validated: false
    };
    var primaryEmail = emailResponse.find(function (emailItem) { return emailItem.primary; });
    if (primaryEmail) {
        email.email = primaryEmail.email;
        email.validated = primaryEmail.verified;
        return email;
    }
    var validatedEmail = emailResponse.find(function (emailItem) { return emailItem.verified; });
    if (validatedEmail) {
        email.email = validatedEmail.email;
        email.validated = validatedEmail.verified;
        return email;
    }
    if (emailResponse.length > 0) {
        var firstEmail = emailResponse[0];
        email.email = firstEmail.email;
        email.validated = firstEmail.verified;
        return email;
    }

    return email;
}

module.exports = github;
