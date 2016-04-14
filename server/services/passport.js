const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

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
passport.use(jwtLogin)