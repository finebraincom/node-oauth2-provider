/**
 * index.js
 * OAuth 2.0 provider
 *
 * @author Amir Malik
 * @author Iurii Kyian
 */

var util = require('util'),
	EventEmitter = require('events').EventEmitter,
	querystring = require('querystring'),
	serializer = require('serializer'),
	_ = require('underscore'),
	CONTENT_TYPE_JSON = {'Content-type': 'application/json'},
	REFRESH_TOKEN_EXTRA = 'refresh';

function parse_authorization(authorization) {
	if(!authorization){
		return null;
	}

	var parts = authorization.split(' ');

	if(parts.length !== 2 || parts[0] !== 'Basic'){
		return null;
	}

	var creds = new Buffer(parts[1], 'base64').toString(),
		i = creds.indexOf(':');

	if(i === -1){
		return null;
	}

	var username = creds.slice(0, i),
		password = creds.slice(i + 1);

	return [username, password];
}

function OAuth2Provider(options){
	if(arguments.length !== 1) {
		console.warn('OAuth2Provider(crypt_key, sign_key) constructor has been deprecated, yo.');

		options = {
			crypt_key: arguments[0],
			sign_key: arguments[1],
		};
	}

	options['authorize_uri'] = options['authorize_uri'] || '/oauth/authorize';
	options['access_token_uri'] = options['access_token_uri'] || '/oauth/access_token';
	options['revoke_uri'] = options['revoke_uri'] || '/oauth/revoke';

	this.options = options;
	this.serializer = serializer.createSecureSerializer(this.options.crypt_key, this.options.sign_key);
}

util.inherits(OAuth2Provider, EventEmitter);

OAuth2Provider.prototype.generateAccessToken = function(user_id, client_id, extra_data, token_options) {
	token_options = token_options || {}
	var out = _.extend(token_options, {
		access_token: this.serializer.stringify([user_id, client_id, +new Date, extra_data]),
		refresh_token: this.serializer.stringify([user_id, client_id, +new Date, REFRESH_TOKEN_EXTRA]),
	});
	return out;
};

OAuth2Provider.prototype.login = function() {
	return _.bind(function(req, res, next) {
    	var data, atok, user_id, client_id, grant_date, extra_data;

    	if(req.query['access_token']){
      		atok = req.query['access_token'];
    	}else if((req.headers['authorization'] || '').indexOf('Bearer ') === 0){
      		atok = req.headers['authorization'].replace('Bearer', '').trim();
    	}else{
      		return next();
    	}

		try {
			data = this.serializer.parse(atok);
			user_id = data[0];
			client_id = data[1];
			grant_date = new Date(data[2]);
			extra_data = data[3];
		}catch(e){
			res.writeHead(400);
			return res.end(e.message);
		}

		this.emit('access_token', req, {
			user_id: user_id,
			client_id: client_id,
			extra_data: extra_data,
			grant_date: grant_date
		}, next);
	}, this);
};

OAuth2Provider.prototype._processAuthrizeUriGet = function (req, res){
	var client_id = req.query.client_id,
		redirect_uri = req.query.redirect_uri;

	if(!client_id || !redirect_uri){
		res.writeHead(400);
		return res.end('client_id and redirect_uri required');
	}

	// authorization form will be POSTed to same URL, so we'll have all params
	var authorize_url = req.url;

	this.emit('enforce_login', req, res, authorize_url, _.bind(function(user_id) {
		// store user_id in an HMAC-protected encrypted query param
		authorize_url += '&' + querystring.stringify({x_user_id: this.serializer.stringify(user_id)});

		// user is logged in, render approval page
		this.emit('authorize_form', req, res, client_id, authorize_url);
	}, this));
};

OAuth2Provider.prototype._processAuthrizeUriPost = function (req, res){
	var client_id = (req.query.client_id || req.body.client_id),
		redirect_uri = (req.query.redirect_uri || req.body.redirect_uri),
		response_type = (req.query.response_type || req.body.response_type) || 'code',
		state = (req.query.state || req.body.state),
		x_user_id = (req.query.x_user_id || req.body.x_user_id);

	var url = redirect_uri;

	switch(response_type) {
		case 'code': 
			url += '?';
			break;
		case 'token':
			url += '#';
			break;
		default:
  			res.writeHead(400);
  			return res.end('invalid response_type requested');
	}

	if('allow' in req.body) {
		if('token' === response_type) {
  			var user_id;

			try{
				user_id = this.serializer.parse(x_user_id);
			}catch(e){
				console.error('allow/token error', e.stack);
				res.writeHead(500);
				return res.end(e.message);
			}

			var ao_redirect_uri = req.query.redirect_uri;
			console.log('request for jwt with redirect_uri ' + ao_redirect_uri);

			this.emit('create_access_token', user_id, client_id, ao_redirect_uri, _.bind(function(extra_data,token_options) {
				var atok = this.generateAccessToken(user_id, client_id, extra_data, token_options);

				if(this.listeners('save_access_token').length > 0){
					this.emit('save_access_token', user_id, client_id, atok);
				}

				url += querystring.stringify(atok);

				res.writeHead(303, {Location: url});
				res.end();
			}, this));
		}else{ // code
			var code = serializer.randomString(128);

			this.emit('save_grant', req, client_id, code, function(){
				var extras = {
					code: code
				};

				// pass back anti-CSRF opaque value
				if(state){
					extras['state'] = state;
				}
				url += querystring.stringify(extras);

				res.writeHead(303, {Location: url});
				res.end();
			});
		}
	} else {
		url += querystring.stringify({error: 'access_denied'});
		res.writeHead(303, {Location: url});
		res.end();
	}
};

OAuth2Provider.prototype._processAccessTokenUriPost = function (req, res){
	var client_id = req.body.client_id,
		client_secret = req.body.client_secret,
		redirect_uri = req.body.redirect_uri,
		code = req.body.code;

	if(!client_id || !client_secret){
		var authorization = parse_authorization(req.headers.authorization);

		if(!authorization) {
			res.writeHead(400);
			return res.end('client_id and client_secret required');
		}

		client_id = authorization[0];
		client_secret = authorization[1];
	}

	if('password' === req.body.grant_type) {
		if(this.listeners('client_auth').length === 0) {
			res.writeHead(401);
			return res.end('client authentication not supported');
		}

		this.emit('client_auth', client_id, client_secret, req.body.username, req.body.password, _.bind(function(err, user_id) {
			if(err) {
				res.writeHead(401);
				return res.end(err.message);
			}

			res.writeHead(200, CONTENT_TYPE_JSON);

			var ao_redirect_uri = req.body.redirect_uri;
			console.log('request for jwt with redirect_uri ' + ao_redirect_uri);
			

			this._createAccessToken(user_id, client_id, ao_redirect_uri, function(atok){
				res.end(JSON.stringify(atok));
			});
		}, this));
	}else if('refresh_token' === req.body.grant_type){
		if(this.listeners('refresh_token_auth').length === 0) {
			res.writeHead(401);
			return res.end('refresh_token not supported');
		}
		var rt_user_id;

		var refresh_token = req.body.refresh_token;
		var isInMigration = req.body.isInMigration || false;

		try {
			var data = this.serializer.parse(refresh_token),
				rt_user_id = data[0],
				rt_client_id = data[1],
				//rt_grant_date = new Date(data[2]),
				rt_extra_data = data[3];
			if (rt_extra_data !== REFRESH_TOKEN_EXTRA){
				console.warn('extra does not match');
				res.writeHead(400);	
				return res.end('invail refresh token');
			}
		}catch(e){
			try {
				refresh_token = decodeURIComponent(refresh_token);
				var data = this.serializer.parse(refresh_token),
					rt_user_id = data[0],
					rt_client_id = data[1],
					//rt_grant_date = new Date(data[2]),
					rt_extra_data = data[3];
				if(rt_client_id !== client_id || rt_extra_data !== REFRESH_TOKEN_EXTRA){
					console.warn('client id or extra does not match');
					res.writeHead(400);	
					return res.end('invail refresh token');
				}
			}catch(e){
				res.writeHead(400);
				return res.end(e.message);
			}		
		}		
		this.emit('refresh_token_auth', client_id, client_secret, refresh_token, isInMigration, _.bind(function(err, user) {
			if(err) {
				res.writeHead(401);
				return res.end(err.message);
			}

			if(user._id.toString() != rt_user_id){
//				console.log(user_id);
				console.warn('refresh token user id does not match');
				res.writeHead(400);	
				return res.end('invalid refresh token');
			}

			this.emit('remove_token', client_id, req.body.refresh_token, 'refresh_token', _.bind(function(err){
				if(err){
					res.writeHead(500);	
					return res.end('fail to refresh token');
				}
				res.writeHead(200, CONTENT_TYPE_JSON);

				var ao_redirect_uri = req.body.redirect_uri;
				console.log('request for jwt with redirect_uri ' + ao_redirect_uri);

				this._createAccessToken(user, client_id, ao_redirect_uri, function(atok){
						res.end(JSON.stringify(atok));
				});
			}, this));
		}, this));
	}else{
		this.emit('lookup_grant', client_id, client_secret, code, _.bind(function(err, user_id){
			if(err){
				res.writeHead(400);
				return res.end(err.message);
			}

			res.writeHead(200, CONTENT_TYPE_JSON);

			var ao_redirect_uri = req.query.redirect_uri;
			console.log('request for jwt with redirect_uri ' + ao_redirect_uri);

			this._createAccessToken(user_id, client_id, ao_redirect_uri, _.bind(function(atok) {
				this.emit('remove_grant', user_id, client_id, code);

				res.end(JSON.stringify(atok));
			}, this));
		}, this));
	}
};

OAuth2Provider.prototype._processRevokeTokenUriPost = function(req, res){
	var token = req.body.token,
		tokenType = req.body.token_type_hint || 'access_token',
		user_id, user_id, client_id;
	if(!token){
		res.writeHead(400);
		return res.end('token required');
	}
	try {
		var data = this.serializer.parse(token), extra_data;
		user_id = data[0];
		client_id = data[1];
		//rt_grant_date = new Date(data[2]);
		extra_data = data[3];
		if(extra_data === REFRESH_TOKEN_EXTRA){
			tokenType = 'refresh_token';
		}
	}catch(e){
		res.writeHead(400);
		return res.end(e.message);
	}		
	this.emit('remove_token', client_id, token, tokenType, function(err){
		if(err){
			res.writeHead(400);
			return res.end(err.message);
		}
		res.writeHead(200, CONTENT_TYPE_JSON);
		res.end(JSON.stringify({success : true}));
	});
};

OAuth2Provider.prototype.oauth = function() {

	return _.bind(function(req, res, next) {
		// extract uri without query parameters
		var uri = ~req.url.indexOf('?') ? req.url.substr(0, req.url.indexOf('?')) : req.url;

		if(req.method === 'GET' && this.options.authorize_uri === uri){
			this._processAuthrizeUriGet(req, res);
		}else if(req.method === 'POST' && this.options.authorize_uri === uri){
			this._processAuthrizeUriPost(req, res);
		}else if(req.method === 'POST' && this.options.access_token_uri === uri){
			this._processAccessTokenUriPost(req, res);
		}else if(req.method === 'POST' && this.options.revoke_uri === uri){
			this._processRevokeTokenUriPost(req, res);
		}else{
			return next();
		}
	}, this);
};

OAuth2Provider.prototype._createAccessToken = function(user, client_id, ao_redirect_uri, cb) {
	console.log('creating access Token with ao_redirect_uri ' + ao_redirect_uri);
	this.emit('create_access_token', user, client_id, ao_redirect_uri, _.bind(function(extra_data, token_options) {
		var atok = this.generateAccessToken(user._id, client_id, extra_data, token_options);

		if(this.listeners('save_access_token').length > 0){
			this.emit('save_access_token', user_id, client_id, atok);
		}

		return cb(atok);
	}, this));
};

exports.OAuth2Provider = OAuth2Provider;
