const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// Define our model
const userSchema = new Schema({
	email: { type: String, unique: true, lowercase: true },
	password: String
});

// create the model class
const ModelClass = mongoose.model('user', userSchema);

// export the model so other things can use it
module.exports = ModelClass;