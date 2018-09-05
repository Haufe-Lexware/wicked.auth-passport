# Outdated Project

This project is/will be outdated as soon as wicked 1.0.0 is released; wicked 1.0.0 contains a default authorization server which is able to perform any task this project could do (plus some more, e.g. SAML).

See also: 

* [http://github.com/Haufe-Lexware/wicked.haufe.io](http://github.com/Haufe-Lexware/wicked.haufe.io)
* [http://github.com/apim-haufe-io/wicked.portal-auth](http://github.com/apim-haufe-io/wicked.portal-auth)

---

# Passport Authorization Server

This is a sample implementation of an Authorization Server which uses a node.js Passport for authenticating a user, and authorizing the user to create access tokens for use with the OAuth 2.0 implicit grant, e.g. for SPAs.

**Please note**: This implementation is intended as either a stub for your own implementation, or as a study object. Before using this in production, you should check thoroughly that it matches your requirements.  

Things to consider before using this component:

* This Authorization Server does not do any kind of Authorization (scopes are not supported),
* The Authentication with any IdP supported by this component is considered enough to authorize the use of the API

## How to use

`auth-passport` supports the following types of identity providers:

* Google
* GitHub
* Facebook
* Twitter

(More to come, pull requests are welcome, it's fairly straight forward, ADFS is next on list).

## Add `auth-passport` to your environment (using `docker-compose`)

For testing purposes, there is a pre-built docker image with this repository you may use.

Incorporate a container with the image `haufelexware/wicked.auth-passport` in your container setup. If you are using `docker-compose`, you will need an additional service:

```yml
version: '2'

services:
  # ...

  auth-passport:
    env_file: variables.env
    image: haufelexware/wicked.auth-passport:dev
    depends_on:
    - portal-api
    - portal-kong-adapter
    command: "npm start"
    restart: unless-stopped
```

In case you are using different deployment methods of your API Portal, this may differ for your setup (e.g. `docker swarm`).

## Configuring Google Login

### Getting a Google Client ID and Secret pair

In order to make the authorization server work, you will need to register it using the Google Developer portal.

This is exactly the same procedure as described for using Google Login for the portal itself, which is described here:

* [Using Google Login for the API Portal](https://github.com/Haufe-Lexware/wicked.haufe.io/blob/master/doc/auth-google.md)

The only thing which really differs (except for names and descriptions) is the callback URI, which has to point to the Authorization Server's callback end point, instead of to the end point of the portal itself. 

If you use the standard setup described below, your callback URL will be: `https://<your api host>/auth-passport/google/callback`.

**Example**: Your portal lives at `https://portal.mycompany.com`, and the API Gateway at `https://api.mycompany.com`, then the Authorization Server's callback URL will be `https://api.mycompany.com/auth-google/callback`.

### Auth-Server Settings

Add the following file called `auth-server.json` in your configuration's `static/auth-servers` directory:

```json
{
  "id": "auth-passport",
  "name": "auth-passport",
  "desc": "Authorization Server based on Social Login",
  "url": "https://${PORTAL_NETWORK_APIHOST}/auth-server/<idp>/api/{{apiId}}?client_id=(your app's client id)&response_type=token&redirect_uri=<your app's redirect uri>[&state=<client state>]",
  "config": {
    "api": {
      "name": "auth-passport",
      "upstream_url": "http://auth-passport:3010",
      "request_path": "/auth-server"
    },
    "plugins": [
      {
        "config": {
          "header_name": "Correlation-Id",
          "generator": "uuid"
        },
        "name": "correlation-id"
      }
    ]
  },
  "urlDescription": "In case you need an access token, call the above link with your `client_id` (for the subscribed API) substituted in the link. In case the authentication with Google is successful, you will get called back at your registered `redirect_uri` with the access token attached in the fragment of the URI. Specify the desired `<idp>`, must be one of `google`, `github`, `twitter` or `facebook` (change to match what you need). Any `state` you pass in will get passed back with the access token, as an additional query parameter `&state=<...>`.",
  "google": {
    "clientId": "<insert google client ID here>",
    "clientSecret": "<insert google client secret here>",
    "callbackUrl": "https://${PORTAL_NETWORK_APIHOST}/auth-server/google/callback"
  }
}
```

This code will expose the authorization server via Kong, at `https://<your api host>/auth-server`, as an API. The upstream URL is defined as `http://auth-passport:3010`, which is implemented by the below compose file entry.

It is advisable to introduce environment variables for `clientId` and `clientSecret`, to (1) be able to have different settings for different environments, and (2) to encrypt (at least) the client secret in your configuration. Use the kickstarter to do this, e.g. by changing the JSON to 

```json
   ...
   "google": {
      "clientId": "${GOOGLE_AUTH_CLIENTID}",
      "clientSecret": "${GOOGLE_AUTH_CLIENTSECRET}",
      "callbackUrl": "https://${PORTAL_NETWORK_APIHOST}/auth-server/google/callback"
   }
```

Then go to the "Environments" and fill in the correct values for the different environments. If you are using a standard setup, the `callbackUrl` will work automatically for all environments if you use the setting above.

### Configuration for GitHub

Extend the `auth-passport.json` file with the following property:

```json
{
   ...
   "github": {
     "clientId": "${GITHUB_AUTH_CLIENTID}",
      "clientSecret": "${GITHUB_AUTH_CLIENTSECRET}",
      "callbackUrl": "https://${PORTAL_NETWORK_APIHOST}/auth-server/github/callback"
   }
}
```

Then fill in the environment variables per environment. Obtain client ID and secret from your Github settings. The callback URL resides at `https://<your api host>/auth-server/github/callback`.

### Configuration for Twitter

Extend the `auth-passport.json` file with the following property:

```json
{
  ...
  "twitter": {
    "consumerKey": "${TWITTER_AUTH_CONSUMERKEY}",
    "consumerSecret": "${TWITTER_AUTH_CONSUMERSECRET}",
    "callbackUrl": "https://${PORTAL_NETWORK_APIHOST}/auth-server/twitter/callback"
  }
}
```

Then fill in the environment variables per environment. Obtain consumer key and secret and register the callback URL in your [Twitter developer portal](https://apps.twitter.com). The callback URL is `https://<your api host>/auth-server/github/callback`.

### Configuration for Facebook

Extend the `auth-passport.json` file with the following property:

```json
{
  ...
  "facebook": {
    "clientId": "${FACEBOOK_AUTH_CLIENTID}",
    "clientSecret": "${FACEBOOK_AUTH_CLIENTSECRET}",
    "callbackUrl": "https://${PORTAL_NETWORK_APIHOST}/auth-server/facebook/callback"
  }
}
```

Then fill in the environment variables per environment. Obtain consumer key and secret and register the callback URL in your [Twitter developer portal](https://apps.twitter.com). The callback URL is `https://<your api host>/auth-server/github/callback`. Facebook accepts multiple callback URLs, so here you may use the same credentials for multiple environments.

## Retrieving generic user profile

The end point `/auth-server/profile` will deliver the generic user profile for the authenticated user (if any); you can use this end point to retrieve data on the user from the browser via an AJAX CORS-enabled call.

The end point will return the following type of JSON structure:

```json
{
  "id": "<idp>:<user-id>",
  "sub": "<idp>:<user-id>",
  "username": "<username, if present, otherwise name>",
  "preferred_username": "<alias for username>",
  "name": "Dan Developer",
  "given_name": "Dan",
  "family_name": "Developer",
  "email": "dan@developer.com",
  "email_verified": true,
  "raw_profile": { /*...*/ }  
}
```

Please note the following restrictions which apply:

* Twitter will NOT allow retrieval of email addresses via the API without manual checking of your application by Twitter
* Facebook also allows user creation without an email addresses (for kids, you know, who just have a phone number), so you can't rely on `email` being filled
* Github allows user creation without an actual name; in that case, the username will be returned as both full name and family name, and given name is left blank
* The same applies to Twitter

This information can be used to pre-fill a registration form in your SPA, but should be allowed to change.

**IMPORTANT**: This end point may be removed in favor of an OpenID Connect type of end point (`/userinfo`) in the future. Currently, some restrictions of the underlying API Gateway does not allow an implementation of OpenID Connect reliably.

## Tweaking runtime behavior

#### Authorization Server base request path

The base request path of the authorization server defaults to `/auth-server`. By setting the environment variable `AUTH_SERVER_BASEPATH` at startup of the authorization server, you can change this, e.g. 

```bash
$ export AUTH_SERVER_BASEPATH=/auth
```

#### Authorization Server Name/ID

The server ID used for retrieving the settings (here we have used `auth-passport.json`, i.e. `auth-passport` as ID) can be changed by setting the environment variable `AUTH_SERVER_NAME` at startup.

```bash
$ export AUTH_SERVER_NAME=social-auth
```

In the example above, the authorization server will search for its setting using the `/auth-servers/social-auth` endpoint of the wicked Portal API.

#### Session Timeout

The session timeout defaults to 60 minutes. This can be changed by overriding the environment variable `AUTH_SERVER_SESSION_MINUTES`:

```bash
$ export AUTH_SERVER_SESSION_MINUTES=15
``` 

## Using in production

If you have plans to use this component in production, it is (currently) advisable to fork your own version of the code and build your own docker image. This image is built directly off the `master` branch and does not run through any particular integration tests (in contrast to the wicked.haufe.io core components).

Right now, we have no plans on actually releasing a `latest` (aka stable) version of this component.

## Container restart

This container will continuously check for the configuration hash (via the `/confighash` end point of the wicked API), which is done automatically by the wicked SDK. In case a configuration change is detected, the container will quit, in the hope that the orchestration layer will restart it automatically.
