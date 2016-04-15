const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

function tokenForUser(user) {
	const timestamp = new Date().getTime();
	return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function (req, res, next) {
	// User has already had their email and password authenticated
	// Now we need to give them a token
	res.send({ token: tokenForUser(req.user) });
}

exports.signup = function(req, res, next) {
	const email = req.body.email;
	const password = req.body.password;

	if ( !email || !password ) {
		return res.status(422).send({ error: 'Email and password must be provided'});
	}

	// see if a user with the given email exists
	User.findOne({ email: email }, function(err, existingUser){
		if (err) { return next(err) };
		// If a user with that email does exist, return an error.
		if (existingUser) {
			return res.status(422).send({ error: 'email is already in use' });
		}
		// If the email has not been used before, create and save user record
		const user = new User({
			email: email,
			password: password
		});

		user.save(function(err) {
			if (err) { return next(err); }

			// Resopond to the request indicating the user was created
			res.json({ token: tokenForUser(user)});
		});
	});
};