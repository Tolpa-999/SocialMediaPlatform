const { text } = require('express');
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail', // or use other services like 'SendGrid', 'Mailgun', etc.
    auth: {
        user: process.env.EMAIL_USER, // your email
        pass: process.env.EMAIL_PASS, // your email password or app password
    },
});


const sendVerificationMail = async (email, title, token) => {
    const verificationLink = `http://localhost:2002/api/users/verify-email?token=${token}`;

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: title,
        html: `Click <a href="${token}">here</a> to ${title}.`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(`Error in sending email => ${error?.message || error}`);
            throw new Error(`Error in sending email => ${error?.message || error}`);
        } else {
            console.log("Email sent: " + info.response);
        }
    });
}

module.exports = {
    sendVerificationMail
}