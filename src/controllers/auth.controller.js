const User = require("../models/user.model");
const jwt = require("jsonwebtoken");
const crypto = require('crypto');

const getProfile = async (req, res) => {
    try {
        res.status(200).json({
            status: "success",
            message: "Get Profile Successfully",
            data: {
                name: req.user.name,
                email: req.user.email
            }
        });
    } catch (error) {
        res.status(500).json({
            status: "fail",
            message: error.message
        });
    }
}

const signup = async (req, res) => {
    try {
        const { name, email, password } = req.body;

        const existingUser = await User.findOne({ email: email });
        if (existingUser) throw new Error("User already exists!");

        /**
         * Here we are using md5 hashing algorithm to hash the password, because bcrypt is not working properly in my personal hosting.
         */
        const hashedPassword = crypto.createHash('md5').update(password).digest('hex');

        const user = await User.create({
            name,
            email,
            password: hashedPassword
        });

        const payload = {
            id: user._id
        };

        const token = jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.status(200).json({
            status: "success",
            message: "Signup Successfully",
            data: {
                user: user,
                token: token
            }
        });
    } catch (error) {
        res.status(400).json({
            status: "fail",
            message: error.message
        });
    }
}

const login = async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email: email });
        if (!user) {
            throw new Error("Invalid email or password!");
        }

        /**
         * Here we are using md5 hashing algorithm to hash the password, because bcrypt is not working properly in my personal hosting.
         */
        const hashedPassword = crypto.createHash('md5').update(password).digest('hex');
        const isEqual = hashedPassword === user.password;
        if (!isEqual) {
            throw new Error("Invalid email or password!");
        }

        const payload = {
            id: user._id
        };

        const token = jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.status(200).json({
            status: "success",
            message: "Login Successfully",
            data: {
                token: token,
                user: user,
            }
        });
    } catch (error) {
        res.status(400).json({
            status: "fail",
            message: error.message
        });
    }
}

module.exports = { getProfile, signup, login };