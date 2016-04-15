const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

// Create Local strategy
const localOptions = { usernameField: 'email' };
const localLogin = new LocalStrategy( localOptions, function(email, password, done) {
	// Verify the email and password, call done with the user if it is correct
	// otherwise, call done with false
	User.findOne({ email: email }, function(err, user) {
		if (err) { return done(err); }
		if (!user) { return done(null, false); }

		// compare passwords: does the given password match the password in the database?
		user.comparePassword(password, function(err, isMatch) {
			if (err) { return done(err); }
			if (!isMatch) { return done(null, false); }

			return done(null, user);
		});
	})
});


// Setup options for JWT Strategy
const jwtOptions = {
	jwtFromRequest: ExtractJwt.fromHeader('authorization'),
	secretOrKey: config.secret
};

// create JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done){
	// See if the user ID in the payload exists in our database
	// if it does, call 'done' with that user
	// otherwise, call 'done' without a user object
	User.findByID(payload.sub, function(err, user){
		if (err) { return done(err, false); }

		if (user) {
			// if we found a user, call done without an error and that user
			done(null, user);
		} else {
			// if we did NOT find a user and there were no errors, call done with null and false
			done(null, false);
		}
	})
});

// Tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);