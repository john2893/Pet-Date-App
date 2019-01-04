// config/auth.js

// expose our config directly to our application using module.exports
module.exports = {

	'facebookAuth' : {
		'clientID' 		: 'your-secret-clientID-here', // your App ID
		'clientSecret' 	: 'your-client-secret-here', // your App Secret
		'callbackURL' 	: 'http://localhost:8080/auth/facebook/callback'
	},

	'twitterAuth' : {
		'consumerKey' 		: 'your-consumer-key-here',
		'consumerSecret' 	: 'your-client-secret-here',
		'callbackURL' 		: 'http://localhost:8080/auth/twitter/callback'
	},

	'googleAuth' : {
		'clientID' 		: '356112378910-ikk453f3m3mn9k5j6cbnmvdo0pj4blss.apps.googleusercontent.com',
		'clientSecret' 	: '3p3KkvVi8CqzNGdJJEr7LZe3',
		'callbackURL' 	: 'http://localhost:8080/auth/google/callback'
	}

};

