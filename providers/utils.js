'use strict';

const cors = require('cors');
const debug = require('debug')('auth-passport:utils');
const wicked = require('wicked-sdk');
const url = require('url');

const utils = function () { };

utils.makeError = function (message, status) {
    const err = new Error(message);
    if (status)
        err.status = status;
    else
        err.status = 500;
    return err;
};

utils.jsonError = function (res, message, status) {
    debug('Error ' + status + ': ' + message);
    res.status(status).json({ message: message });
};

utils.getJson = function (ob) {
    if (ob instanceof String || typeof ob === "string")
        return JSON.parse(ob);
    return ob;
};

// Whoa, this is closures galore.
utils.verifyClientAndAuthenticate = function (idpName, passportAuthenticate) {
    return function (req, res, next) {
        const apiId = req.params.apiId;
        const clientId = req.query.client_id;
        const responseType = req.query.response_type;
        const givenRedirectUri = req.query.redirect_uri;
        const givenState = req.query.state;
        debug('/' + idpName + '/api/' + apiId + '?client_id=' + clientId + '&response_type=' + responseType);
        if (givenState)
            debug('given state: ' + givenState);

        if (!clientId)
            return next(utils.makeError('Bad request. Query parameter client_id is missing.', 400));
        if (responseType !== 'token')
            return next(utils.makeError('Bad request. Parameter response_type is missing or faulty. Currently, only "token" is supported.', 400));
        // Check whether we need to bother Google or not.
        wicked.getSubscriptionByClientId(clientId, apiId, function (err, subsInfo) {
            if (err)
                return next(err);

            // console.log(JSON.stringify(subsInfo, null, 2));

            // Yes, we have a valid combination of API and Client ID
            // Store data in the session.
            const redirectUri = subsInfo.application.redirectUri;

            if (givenRedirectUri && givenRedirectUri !== redirectUri)
                return next(utils.makeError('Bad request. redirect_uri mismatch.', 400));

            req.session.apiId = apiId;
            req.session.clientId = clientId;
            req.session.redirectUri = redirectUri;
            req.session.responseType = responseType;
            if (givenState)
                req.session.state = givenState;
            else if (req.session.state)
                delete req.session.state;

            req.session.userValid = false;

            // Remember the host of the redirectUri to allow CORS from it:
            storeRedirectUriForCors(redirectUri);

            // Off you go with passport:
            passportAuthenticate(req, res, next);
        });
    };
};

utils.authorizeAndRedirect = function (idpName, authServerName) {
    return function (req, res, next) {
        debug('/' + idpName + '/callback');

        if (!req.session ||
            !req.session.passport ||
            !req.session.passport.user ||
            !req.session.passport.user.id)
            return next(utils.makeError('Could not retrieve authenticated user id from session.', 500));

        const authenticatedUserId = req.session.passport.user.id;
        const clientId = req.session.clientId;
        const apiId = req.session.apiId;

        // This shouldn't happen...
        if (!clientId || !apiId)
            return next(utils.makeError('Invalid state, client_id and/or API id not known.', 500));

        // Now get a token puhlease.
        // Note: We don't use scopes here.
        const userInfo = {
            authenticated_userid: authenticatedUserId,
            client_id: clientId,
            api_id: apiId,
            auth_server: authServerName
        };
        wicked.oauth2AuthorizeImplicit(userInfo, function (err, result) {
            if (err)
                return next(err);
            if (!result.redirect_uri)
                return next(utils.makeError('Did not receive a redirect_uri from Kong Adapter.', 500));
            // Yay
            req.session.userValid = true;

            let clientRedirectUri = result.redirect_uri;
            // If we were passed a state, give that state back
            if (req.session.state)
                clientRedirectUri += '&state=' + req.session.state;

            // Redirect back, the access token is in the fragment of the URI.
            res.redirect(clientRedirectUri);
        });
    };
};

utils.splitName = function (fullName, username) {
    debug('splitName(): fullName = ' + fullName + ', username = ' + username);
    var name = {
        firstName: '',
        lastName: fullName,
        fullName: fullName
    };
    if (!fullName) {
        if (username) {
            name.lastName = username;
            name.fullName = username;
        } else {
            name.lastName = 'Unknown';
            name.fullName = 'Unknown';
        }
    } else {
        var spaceIndex = fullName.indexOf(' ');
        if (spaceIndex < 0)
            return name;
        name.firstName = fullName.substring(0, spaceIndex);
        name.lastName = fullName.substring(spaceIndex + 1);
    }
    debug(name);
    return name;
};

utils.makeUsername = function (fullName, username) {
    debug('makeUsername(): fullName = ' + fullName + ', username = ' + username);
    if (username)
        return username;
    return fullName;
};

const _validCorsHosts = {};
function storeRedirectUriForCors(uri) {
    debug('storeRedirectUriForCors() ' + uri);
    try {
        const parsedUri = url.parse(uri);
        const host = parsedUri.protocol + '//' + parsedUri.host;
        _validCorsHosts[host] = true;
        debug(_validCorsHosts);
    } catch (ex) {
        console.error('storeRedirectUriForCors() - Invalid URI: ' + uri);
    }
}

function isCorsHostValid(host) {
    debug('isCorsHostValid(): ' + host);
    if (_validCorsHosts[host]) {
        debug('Yes, ' + host + ' is valid.');
        return true;
    }
    debug('*** ' + host + ' is not a valid CORS origin.');
    return false;
}

const _allowOptions = {
    origin: true,
    credentials: true,
    allowedHeaders: [
        'Accept',
        'Accept-Encoding',
        'Connection',
        'User-Agent',
        'Content-Type',
        'Cookie',
        'Host',
        'Origin',
        'Referer'
    ]
};

const _denyOptions = {
    origin: false
};

utils.cors = function () {
    const optionsDelegate = (req, callback) => {
        const origin = req.header('Origin');
        debug('in CORS options delegate. req.headers = ');
        debug(req.headers);
        if (isCorsHostValid(origin))
            callback(null, _allowOptions); // Mirror origin, it's okay
        else
            callback(null, _denyOptions);
    };
    return cors(optionsDelegate);
};

module.exports = utils;