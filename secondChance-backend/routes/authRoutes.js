const express = require('express');
const router = express.Router();
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const connectToDatabase = require('../models/db');
const logger = require('../logger');

// Register endpoint
router.post('/register', async (req, res, next) => {
    try {
        // Step 1: Connect to MongoDB
        const db = await connectToDatabase();
        
        // Step 2: Access users collection
        const collection = db.collection('users');

        // Step 3: Check if user credentials already exist in database
        const { email } = req.body;
        const existingUser = await collection.findOne({ email });
        
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists with this email' });
        }

        // Step 4: Create a hash to encrypt the password
        const { password } = req.body;
        const salt = await bcryptjs.genSalt(10);
        const hashedPassword = await bcryptjs.hash(password, salt);

        // Step 5: Insert the user into the database
        const { firstName, lastName } = req.body;
        const newUser = await collection.insertOne({
            email,
            firstName,
            lastName,
            password: hashedPassword,
            createdAt: new Date()
        });

        // Step 6: Create JWT authentication with user._id as payload
        const payload = {
            user: {
                id: newUser.insertedId
            }
        };

        const authToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Step 7: Log the successful registration
        logger.info('User registered successfully');

        // Step 8: Return the user email and token as JSON
        res.status(201).json({
            authToken,
            email
        });

    } catch (e) {
        next(e);
    }
});

module.exports = router;
