'use strict';
/* jshint loopfunc: true */

const passport = require('passport');
const debug = require('debug')('auth-passport:adfs');
const OAuth2Strategy = require('passport-oauth').OAuth2Strategy;
const jwt = require('jsonwebtoken');
const wicked = require('wicked-sdk');

const adfs = require('express').Router();

const utils = require('./utils');

adfs.authenticateSettings = {
    failureRedirect: '/auth-server/failure'
};

adfs.init = function (app, authConfig) {
    debug('init()');
    adfs.authServerName = app.get('server_name');
    adfs.basePath = app.get('base_path');
    if (!authConfig.adfs) {
        debug('Not configuring ADFS authentication.');
        return;
    }

    adfs.authenticateSettings.failureRedirect = adfs.basePath + '/failure';

    if (!authConfig.adfs.clientId)
        throw new Error('In auth-server configuration, property "adfs", the property "clientId" is missing.');
    if (!authConfig.adfs.clientSecret)
        throw new Error('In auth-server configuration, property "adfs", the property "clientSecret" is missing.');
    if (!authConfig.adfs.callbackUrl)
        throw new Error('In auth-server configuration, property "adfs", the property "callbackUrl" is missing.');
    if (!authConfig.adfs.tokenUrl)
        throw new Error('In auth-server configuration, property "adfs", the property "tokenUrl" is missing.');
    if (!authConfig.adfs.authorizationUrl)
        throw new Error('In auth-server configuration, property "adfs", the property "authorizationUrl" is missing.');
    if (!authConfig.adfs.resource)
        throw new Error('In auth-server configuration, property "adfs", the property "resource" is missing.');
    if (authConfig.adfs.verifyCert && !authConfig.adfs.publicCert)
        throw new Error('In auth-server configuration, property "adfs", verifyCert is set to true and the property "publicCert" is missing.');

    if (!authConfig.adfs.profile)
        throw new Error('In auth-server configuration, property "adfs", the property "profile" is missing.');
    if (!authConfig.adfs.profile.id)
        throw new Error('In auth-server configuration, property "adfs.profile", the property "id" is missing.');
    if (!authConfig.adfs.profile.family_name)
        throw new Error('In auth-server configuration, property "adfs.profile", the property "family_name" is missing.');
    if (!authConfig.adfs.profile.given_name)
        throw new Error('In auth-server configuration, property "adfs.profile", the property "given_name" is missing.');
    if (!authConfig.adfs.profile.email)
        throw new Error('In auth-server configuration, property "adfs.profile", the property "email" is missing.');

    if (authConfig.adfs.scopes) {
        debug('Detected scopes');
        debug(JSON.stringify(authConfig.adfs.scopes));
        // Normalize all group names to lowercase
        const tempScopes = {};
        for (let key in authConfig.adfs.scopes) {
            tempScopes[key.toLowerCase()] = authConfig.adfs.scopes[key];
        }
        debug('Lower cased ADFS group names:');
        debug(JSON.stringify(tempScopes));
        authConfig.adfs.scopes = tempScopes;
    }

    // Here we need to pass in the explicit name of the strategy,
    // as OAuth2Strategy is a generic strategy, in contrast to the other ones.
    passport.use('adfs', new OAuth2Strategy({
        authorizationURL: authConfig.adfs.authorizationUrl,
        tokenURL: authConfig.adfs.tokenUrl,
        clientID: authConfig.adfs.clientId, // This is the ID of the ADFSClient created in ADFS via PowerShell
        clientSecret: authConfig.adfs.clientSecret, // This is ignored but required by the OAuth2Strategy
        callbackURL: authConfig.adfs.callbackUrl,
        passReqToCallback: true
    }, function (req, accessToken, refreshToken, profile, done) {
        debug('ADFS Authentication');
        var decodedProfile = null;
        // Verify Token with Certificate?
        if (authConfig.adfs.verifyCert) {
            try {
                // Decode Oauth token and verify that it has been signed by the given public cert
                decodedProfile = jwt.verify(accessToken, authConfig.adfs.publicCert);
                debug('Verified JWT successfully.');
            } catch (ex) {
                console.error('ERROR: Could not verify JWT');
                return done(null, false, { message: ex });
            }
        }
        else {
            decodedProfile = jwt.decode(accessToken);
        }

        debug(decodedProfile);

        normalizeProfile(decodedProfile, authConfig, function (err, normalizedProfile) {
            if (err) {
                console.error('ADFS normalizeProfile failed.');
                console.error(err);
                console.error(err.stack);
                return done(err);
            }
            debug('Normalized ADFS profile');
            debug(normalizedProfile);

            return done(null, normalizedProfile);
        });
    }));

    const authenticateWithAdfs = passport.authenticate('adfs');
    const authenticateCallback = passport.authenticate('adfs', adfs.authenticateSettings);

    adfs.get('/api/:apiId', utils.verifyClientAndAuthenticate('adfs', authenticateWithAdfs));
    adfs.get('/callback', authenticateCallback, utils.authorizeAndRedirect('adfs', adfs.authServerName));

    debug('Configured ADFS authentication.');
};

function normalizeProfile(profile, authConfig, callback) {
    const familyName = profile[authConfig.adfs.profile.family_name];
    const givenName = profile[authConfig.adfs.profile.given_name];

    const userProfile = {
        id: 'adfs:' + profile[authConfig.adfs.profile.id],
        sub: 'adfs:' + profile[authConfig.adfs.profile.id],
        username: profile[authConfig.adfs.profile.id],
        preferred_username: profile[authConfig.adfs.profile.id],
        name: utils.makeFullName(familyName, givenName),
        given_name: givenName,
        family_name: familyName,
        email: profile[authConfig.adfs.profile.email],
        email_verified: true, // trust ADFS by default
        scope: getScope(profile, authConfig),
        raw_profile: profile,
    };

    return callback(null, userProfile);
}

function getScope(profile, authConfig) {
    if (!authConfig.adfs.scopes) {
        debug('scopes are not defined in adfs config, skipping.');
        return null;
    }

    // Let's normalize to lower case, that's what we stored in the authConfig
    const groups = [];
    for (let i = 0; i < profile.group.length; ++i) {
        groups.push(profile.group[i].toLowerCase());
    }

    const scope = [];
    for (let i = 0; i < groups.length; ++i) {
        const group = groups[i];
        debug('Checking for scopes for group ' + group);
        if (authConfig.adfs.scopes[group]) {
            const groupScope = authConfig.adfs.scopes[group];
            debug('Found a scope entry: ' + groupScope);
            if (!Array.isArray(groupScope)) {
                console.error('Scope entry for group ' + groupScope + ' is not an array.');
                continue;
            }
            for (let j = 0; j < groupScope.length; ++j) {
                // Already in list?
                if (scope.indexOf(groupScope[j]) === -1) {
                    // Nope.
                    scope.push(groupScope[j]);
                }
            }
        }
    }
    debug('Resulting scope: ' + JSON.stringify(scope));
    return scope;
}

module.exports = adfs;
