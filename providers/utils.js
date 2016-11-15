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
        debug('/' + idpName + '/api/' + apiId + '?client_id=' + clientId);
        debug('req headers:');
        debug(req.headers);

        if (!clientId)
            return next(utils.makeError('Bad request. Query parameter client_id is missing.', 400));
        // Check whether we need to bother Google or not.
        wicked.getSubscriptionByClientId(clientId, apiId, function (err, subsInfo) {
            if (err)
                return next(err);

            // console.log(JSON.stringify(subsInfo, null, 2));

            // Yes, we have a valid combination of API and Client ID
            // Store data in the session.
            const redirectUri = subsInfo.application.redirectUri;
            req.session.apiId = apiId;
            req.session.clientId = clientId;
            req.session.redirectUri = redirectUri;
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
            authenticated_userid: idpName + ':' + authenticatedUserId,
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

            // Redirect back, the access token is in the fragment of the URI.
            res.redirect(result.redirect_uri);
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

utils.cors = function () {
    const optionsDelegate = (req, callback) => {
        const origin = req.header('Origin');
        if (isCorsHostValid(origin))
            callback(null, { origin: true, credentials: true }); // Mirror origin, it's okay
        else
            callback(null, { origin: false });
    };
    return cors(optionsDelegate);
};

module.exports = utils;