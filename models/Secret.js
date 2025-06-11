const mongoose = require('mongoose');

const secretSchema = new mongoose.Schema({
  content: String,
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  }
});

module.exports = mongoose.model('Secret', secretSchema);