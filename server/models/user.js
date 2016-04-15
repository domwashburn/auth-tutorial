const mongoose = require('mongoose');
const bcrypt = require('bcrypt-nodejs');
const Schema = mongoose.Schema;

// Define our model
const userSchema = new Schema({
	email: { type: String, unique: true, lowercase: true },
	password: String
});

// on save hook, encrypt the password
// before the model gets saved, run this (.pre)
userSchema.pre('save', function(next) {
	// get access to the instance of the user model
	const user = this;

	// generate a salt then run the callback function
	bcrypt.genSalt(10, function(err, salt) {
		if (err) { return next(err); }

		// hash (encrypt) our password using the salt
		bcrypt.hash(user.password, salt, null, function(err, hash) {
			if (err) { return next(err); }

			// overwrite plain text password with the encrypted password
			user.password = hash;
			next();
		})
	})
});

userSchema.methods.comparePassword = function( candidatePassword, callback ) {
	bcrypt.compare( candidatePassword, this.password, function(err, isMatch) {
		if (err) { return callback(err); }

		callback( null, isMatch );
	} )
}

// create the model class
const ModelClass = mongoose.model('user', userSchema);

// export the model so other things can use it
module.exports = ModelClass;