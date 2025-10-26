const express = require('express');
const router = express.Router();
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
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

// Login endpoint
router.post('/login', async (req, res, next) => {
    try {
        // Step 1: Connect to MongoDB
        const db = await connectToDatabase();

        // Step 2: Access the MongoDB users collection
        const collection = db.collection('users');

        // Step 3: Check for user credentials in the database
        const { email } = req.body;
        const user = await collection.findOne({ email });

        // Step 4: Check if the password entered matches the stored encrypted password
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const { password } = req.body;
        const isMatch = await bcryptjs.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Step 5: Fetch user details from the database
        const userName = user.firstName;
        const userEmail = user.email;

        // Step 6: Create JWT authentication with user._id as payload
        const payload = {
            user: {
                id: user._id
            }
        };

        const authtoken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Step 7: Log the successful login
        logger.info('User logged in successfully');
        return res.status(200).json({ authtoken, userName, userEmail });

    } catch (e) {
        next(e);
    }
});

// Update endpoint
router.put('/update', async (req, res, next) => {
    try {
        // Validate input
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        // Check if email is present in the header
        const email = req.headers.email;
        if (!email) {
            return res.status(400).json({ error: 'Email is required in the header' });
        }

        // Connect to MongoDB
        const db = await connectToDatabase();

        // Access the users collection
        const collection = db.collection('users');

        // Find the user credentials in the database
        const user = await collection.findOne({ email });

        if (!user) {
            logger.error('User not found');
            return res.status(404).json({ error: "User not found" });
        }


        const update = { ...req.body, updatedAt: new Date() };

        // Update the user credentials in the database
        const updatedUser = await collection.findOneAndUpdate(
            { email },
            { $set: update },
            { returnDocument: 'after' }
        );

        // Create JWT authentication with user._id as payload
        const payload = {
            user: {
                id: updatedUser._id
            }
        };

        const authToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
        logger.info('User updated successfully');
        res.json({ authToken });

    } catch (e) {
        return res.status(500).send("Internal Server Error");
    }
});

module.exports = router;
