'use strict';
/* jshint loopfunc: true */

const adfs = require('express').Router();
const passport = require('passport');
//const request = require('request');
const debug = require('debug')('auth-passport:adfs');
const oauth2Strategy = require('passport-oauth').OAuth2Strategy;
const jwt = require('jsonwebtoken');
// const fs = require('fs');
const wicked = require('wicked-sdk');

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
    if (!authConfig.adfs.authorizeUrl)
        throw new Error('In auth-server configuration, property "adfs", the property "authorizeUrl" is missing.');
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

    
};