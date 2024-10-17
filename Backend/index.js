require('dotenv').config()


const cookieParser = require("cookie-parser");


const cors = require("cors");
const express = require("express")
const app = express();
// const path = require("path")

app.use(cors())

const mongoose = require("mongoose")
const url = process.env.MONGO_URL;
mongoose.connect(url, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('Connected Succesfully');
}).catch((error) => {
    console.error(error);
})


// async function listIndexes() {
//     try {
//         await mongoose.connect(process.env.MONGO_URL, {
//             useNewUrlParser: true,
//             useUnifiedTopology: true,
//         });

//         await User.collection.dropIndexes()
//         console.log('userName index dropped successfully.');

//         await mongoose.disconnect();
//     } catch (error) {
//         console.error(error);
//     }
// }

// listIndexes();




const httpStatus = require('./utils/httpStatusText')

app.use(cookieParser());
app.use(express.json());

const userController = require('./routes/users.routes');
const User = require('./models/users.model');
app.use('/api/users', userController)

app.all("*", (req, res) => {
    res.status(404).json({ status: httpStatus.ERROR, message: "resource not availble" })
})

app.use((error, req, res, next) => {
    res.status(error.statusCode || 500).json({ status: error.statusText || httpStatus.ERROR, message: error.message, code: error.statusCode || 500, data: null })
})


app.listen(process.env.PORT || 2002, () => {
    console.log("listening on port 2002")
})

module.exports = app; 