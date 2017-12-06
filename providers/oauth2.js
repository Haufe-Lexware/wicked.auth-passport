'use strict';

const request = require('request');
const passport = require('passport');
const OAuth2Strategy = require('passport-oauth').OAuth2Strategy;
const wicked = require('wicked-sdk');
const debug = require('debug')('auth-passport:oauth2');
const jwt = require('jsonwebtoken');

const utils = require('./utils');

const oauth2 = require('express').Router();

oauth2.authenticateSettings = {
    failureRedirect: '/auth-server/failure'
};

oauth2.init = function (app, authConfig) {
    debug('init()');
    oauth2.authServerName = app.get('server_name');
    oauth2.basePath = app.get('base_path');
    if (!authConfig.oauth2) {
        debug('Not configuring oauth2 authentication.');
        return;
    }

    oauth2.authenticateSettings.failureRedirect = oauth2.basePath + '/failure';

    if (!authConfig.oauth2.clientId)
        throw new Error('In auth-server configuration, property "oauth2", the property "clientId" is missing.');
    if (!authConfig.oauth2.clientSecret)
        throw new Error('In auth-server configuration, property "oauth2", the property "clientSecret" is missing.');
    if (!authConfig.oauth2.callbackUrl)
        throw new Error('In auth-server configuration, property "oauth2", the property "callbackUrl" is missing.');
    if (!authConfig.oauth2.authorizationURL)
        throw new Error('In auth-server configuration, property "oauth2", the property "authorizationURL" is missing.');
    if (!authConfig.oauth2.tokenURL)
        throw new Error('In auth-server configuration, property "oauth2", the property "tokenURL" is missing.');

    passport.use(new OAuth2Strategy({
        clientID: authConfig.oauth2.clientId,
        clientSecret: authConfig.oauth2.clientSecret,
        callbackURL: authConfig.oauth2.callbackUrl,
        authorizationURL: authConfig.oauth2.authorizationURL,
        tokenURL: authConfig.oauth2.tokenURL,
        passReqToCallback: true
    }, function (accessToken, refreshToken, profile, done) {
        debug('Oauth2 Authenticate succeeded.');
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

    const authenticateWithOauth2 = passport.authenticate('oauth2', { scope: ['user:email'] });
    const authenticateCallback = passport.authenticate('oauth2', oauth2.authenticateSettings);

    oauth2.get('/api/:apiId', utils.verifyClientAndAuthenticate('oauth2', authenticateWithOauth2));
    oauth2.get('/callback', authenticateCallback, utils.authorizeAndRedirect('oauth2', oauth2.authServerName));

    debug('Configured oauth2 authentication.');
};

function normalizeProfile(profile, accessToken, callback) {
    debug('normalizeProfile()');
    var decodedProfile = jwt.decode(accessToken);
    var defaultGroups = [];
    if(decodedProfile['group']){
      defaultGroups = decodedProfile['group'];
    }
    const userProfile = {
      customId: decodedProfile[authConfig.oauth2.customIdField],
      firstName: decodedProfile[authConfig.oauth2.firstNameField],
      lastName: decodedProfile[authConfig.oauth2.lastNameField],
      validated: true, // In Oauth2 we trust
      groups: defaultGroups,
      email: decodedProfile[authConfig.oauth2.emailField]
    };
    return callback(null, userProfile);
}

module.exports = oauth2;
