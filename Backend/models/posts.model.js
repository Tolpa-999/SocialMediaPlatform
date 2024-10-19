const mongoose = require('mongoose')
const postSchema = new mongoose.Schema({
    content: {
        type: String,
        required: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User', // Referencing the User model
        required: true,
    },
});

const Post = mongoose.model('Post', postSchema);
module.exports = Post;