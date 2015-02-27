# OAuth 2 Provider for Connect & Express

This is a node.js module for implementing OAuth2 servers (providers)
that support server-side (code) and client-side (token) OAuth flows.

It's very customizable, so you can (and currently, must) take care of
OAuth token storage and client lists. In the future, a Mongo or Redis
backed abstraction will be provided so you don't need to care about
any kind of storage at all.

## Using it with npm

If you're using this module via npm, please be sure the bracket the
version in your app's `package.json` file. Major versions may have an
incompatible API that's not backwards-compatible, so use a safe version
range under `dependencies` (eg. for version 1.x):

    "oauth2-provider": "1.x"

## Quick Start

Install via npm:

    npm install oauth2-provider

You can add it to your Connect or Express application as another middleware.
Be sure to enable the `bodyParser` and `query` middleware.

The OAuth2Provider instance providers two middleware:

* `oauth()`: OAuth flow entry and access token generation
* `login()`: Access control for protected resources

The most important event emitted by OAuth2Provider is `access_token`, which
lets you set up the request as if it were authenticated. For example, to
support both cookie-authenticated and OAuth access to protected URLs, you
could populate `req.session.user` so that individual URLs don't need to
care about which type of authentication was used.

To support client authentication (sometimes known as xAuth) for trusted
clients, handle the `client_auth` event to exchange a username and password
for an access token. See `examples/simple_express4/app.js`.

## Example

Within the examples sub-folder matching your preferred version of Express (for example, `examples/simple_express4`), run `npm install` and then run:

    node app.js

Visit <http://localhost:8081/login> to gain access to
<http://localhost:8081/secret> or use OAuth to obtain an access token as a code (default) or a token (in the URL hash):

  - code: <http://localhost:8081/oauth/authorize?client_id=1&redirect_uri=http://myapp.foo/>
  - token: <http://localhost:8081/oauth/authorize?client_id=1&redirect_uri=http://myapp.foo/&response_type=token>

Provider Configuration
======================

Constructor recieves options which setup provider configuration:

Option | Description
-------|-------------
authorize_uri    | path for processing authorization requests (default: `/oauth/authorize`)
access_token_uri | path for processing token requests (default: `/oauth/access_token`)
revoke_uri       | path for processing token revoking requests (default: `/oauth/revoke`)
crypt_key        | string used for tokens encryption
sign_key         | string used for tokens signing

	var provider = new require('oauth2-profider')(options);

`login()` middleware
====================

1. Attempts to extract access_token from:
	* query parameter 'access_token'
	* 'authorization' header ('Bearer <token value>')
2. parses found access token (if cann't parse report status code 400)
3. emits event 'access_token' on provider if token valid with parsed token data
4. passes control to next() in the middleware chain
5. if access token is not found just pass control to next() in the middleware chain

##### 'access_token' event handler

	function(req, token, next) {
		// 1. lookup the token in known tokens
		// 2. find user of the token
		// 3. save user in the sessionin the session
		next();
	}

In case if token is expired or user is not found does not save user in the session. This means that user is not authorized.

`token` parameter content:

	{
		user_id: user_id,
		client_id: client_id,
		extra_data: extra_data,
		grant_date: grant_date
	}

`oauth()` middleware
====================

Handlers for 

*  authorization GET requests
*  authorization POST requests
*  access token POST requests
*  revoke token POST requests

See details in the corresponding sections


Authorization GET requests
==========================

GET requests that come with path, defined in `authorize_uri` option.

Presents authorization form. If the user is not already logged in allows to login.
Forms rendering is delegated to module client throught events emitting.

Expected query string parameters:

Parameter|Meaning
---------|-------
client_id|client id of the caller
redirect_uri| url for redirect after successfull authentication

During processing the request the provider emits 2 events:

#### 'enforce_login'

The handler has signature:

	function(req, res, authorize_url, next) {
		//1. if user already logged in call next() with user id
		//2. if user is not logged in redirect him to login form and do not call next()
	}

#### 'authorize_form'

The handler has signature:

	function(req, res, client_id, authorize_url) {
		// Render authorization form with buttons allow/deny (name='allow|deny').
		// Use method POST that point to `authorize_url`.
	}

Authorization POST requests
===========================

POST requests that come with path, defined in `authorize_uri` option.
Process authorization form submission request.

Expects recieving parameters through query string or body of the request.

Parameter|Meaning
---------|-------
client_id|client id of the caller (comes from authorization form)
redirect_uri| url for redirect after successfull authentication (comes from authorization form)
x_user_id| encoded user id recieved in Authorization GET request (comes from authorization form)
response_type| type of the response (default: `code`): <ul><li>`code` - client expects recieving auth code that can be exchanged for access token</li><li>`token` - client expects recieving access token</li></ul>
state| optional state information that will be added as `state` parameter in the redirect url

If the request comes without value 'allow' in the request body it is treated as authorization rejected by the user. Request results in redirect to 'redirect_uri' with appending query string parameter `error` with value 'access_denied'.

authorization with recieving `auth code`
----------------------------------------

During processing the request the provider emits event:

##### 'save_grant'

	function(req, client_id, code, next){
		// save code for later exchange for access token
		next();
	}

After successfull authorization client redirected to `redirect_uri` with 'code` appended to url as query string parameter.


authorization with recieving `access token`
-------------------------------------------

During processing the request the provider emits 2 events:

##### 'create_access_token'

	function(user_id, client_id, next) {
		// allows to put some custom data into access token
		next('extra_data');
	}

##### 'save_access_token'

	function(user_id, client_id, access_token) {
		// saves access token for later retrieval
	}

After successfull authorization client redirected to `redirect_uri` with 'access_token` and `refresh_token` appended to url after hash (#) as query string parameters.

Access token POST requests
==========================

POST requests that come with path, defined in `access_token_uri` option.
Performs token related operations

'Auth code' exchange for 'access token'
---------------------------------------

Expects recieving parameters through body of the request.

Parameter|Meaning
---------|-------
client_id|client id of the caller
client_secret|client secret of the caller
code| auth code to exchange for access token

Returns JSON with tokens:

	```json
	{
		"access_token" : "<value>",
		"refresh_token" : "<value>""
	}
	```

During processing the request the provider emits 2 events:

##### 'lookup_grant'

	function(client_id, client_secret, code, next) {
		// 1. checks for presence of previously save auth code
		// 2. checks it validity of the code (not expired)
		// 3. finds the user who created the code and return it in call `next(null, user_id)`
		// 4. in case of a failed check report it with error as first parameter in `next()`
	}

##### 'remove_grant'

	function(user_id, client_id, code) {
		// remove code already echanged for access_token
	}

Generate new 'access token' from 'refresh token'
------------------------------------------------

Expects recieving parameters through body of the request.

Parameter|Meaning
---------|-------
client_id|client id of the caller
client_secret|client secret of the caller
grant_type|`refresh_token`
refresh_token| refresh token value

In case of success returns JSON with tokens:

	```json
	{
		"access_token" : "<value>",
		"refresh_token" : "<value>""
	}
	```

During processing the request the provider emits 4 events:

##### 'refresh_token_auth'

	function(client_id, client_secret, refresh_token, next){
		// 1. validates client and refresh token validity by cheking it presence in save tokens
		// 2. find user of the refresh token and report it to `next(null, user_id)`
		// 3. in case of failed check report as first parameter in `next()`
	}

##### 'remove_token'
	function(client_id, token, token_type, next){
		//1. remove token by type ('access_token' or 'refresh_token')
		// 2. call `next()` on success
		// 3. in case of failed check report as first parameter in `next()`
	}

##### 'create_access_token'
(see above)

##### 'save_access_token'
(see above)

Generate new 'access token' from 'password' grand_type
------------------------------------------------------

Expects recieving parameters through body of the request.

Parameter|Meaning
---------|-------
client_id|client id of the caller
client_secret|client secret of the caller
grant_type|`password`
username|user name for authorization
password|user password for authorization

In case of success returns JSON with tokens:

	```json
	{
		"access_token" : "<value>",
		"refresh_token" : "<value>""
	}
	```

During processing the request the provider emits 3 events:

##### 'client_auth'

	function(client_id, client_secret, username, password, next) {
		// 1. checks that client id and secret are valid
		// 2. check that user credentials are valid
		// 3. report user id in `next(null, user_id)`
		// 4. in case of failed check report as first parameter in `next()`
	}

##### 'create_access_token'
(see above)

##### 'save_access_token'
(see above)

Revoke token POST requests
==========================

Revokes token

Parameter|Meaning
---------|-------
token|token value
token_type_hint|type of token (optional, can be detected from token content) <ul><li>`access_token`</li><li>`refresh_token`</li></ul>

On success return JSON:

	```json
	{
		"success" : true
	}```

During processing the request the provider emits event:

##### 'remove_token'

	function(client_id, token, token_type, next){
		// remove token of the specific type
		// in case of failed check report as first parameter in `next()`
		next();
	}


## Running tests

  Install dev dependencies:

    $ npm install -d

  Run the tests:

    $ make test
