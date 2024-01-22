const express = require('express');
const { MongoClient} = require('mongodb');
const dotenv = require('dotenv');


const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const nodemailer = require('nodemailer');

const jsonwebtoken = require('jsonwebtoken');


dotenv.config();
const cors = require("cors")

const app = express();
const PORT = 5000;
app.use(cors())
// MongoDB connection string
const URL = process.env.DB;

// Connect to MongoDB
let db;

MongoClient.connect(URL)
  .then((client) => {
    db = client.db();
    console.log('Connected to MongoDB');
  })
  .catch((err) => console.error('Error connecting to MongoDB:', err));

// Middleware
app.use(express.json());
// Registration endpoint
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    // Check if the username or email already exists
    const existingUser = await db.collection('users').findOne({ $or: [{ username }, { email }] });

    if (existingUser) {
      return res.status(409).json({ message: 'Username or email already exists' });
    }

    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save user data to the database
    const result = await db.collection('users').insertOne({
      username,
      email,
      password: hashedPassword,
    });

    res.status(201).json({ message: 'User registered successfully', userId: result.insertedId });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// API endpoint for user login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Find the user by username
    const user = await db.collection('users').findOne({ username });
    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Compare the provided password with the hashed password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Generate a JWT token
    const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
   
    // Send user details along with the token
    res.json({
      token,
      user: {
        userId: user._id,
        username: user.username,
        token,
       
       
      },
    });
  

   console.log('login');
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    const user = await db.collection('users').findOne({ email });

    if (!user) {
      console.log('User not registered');
      return res.status(404).json({ message: 'User not registered' });
    }

    const token = jsonwebtoken.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    await db.collection('users').updateOne({ email }, {
      $set: { token }
    });

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    const info = await transporter.sendMail({
      from: process.env.MAIL_ID,
      to: email,
      subject: 'Reset password link',
      text: `Click the following link to reset your password: /reset-password/${token}`
    });

    console.log('Password reset link sent successfully.');
    res.json({ message: 'Password reset link sent successfully.' });
  } catch (error) {
    console.error('Failed to send password reset email:', error);
    res.status(500).json({ message: 'Failed to send password reset email.' });
  }
});
app.post("/reset-password/:token", async (req, res) => {
  try {
    const { password, confirmPassword } = req.body;
    let token = req.params.token;

    // Remove leading colon if present
    token = token.replace(/^:/, '');

    jsonwebtoken.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
      if (err) {
        console.error('Error with token:', err);
        return res.status(400).json({ message: 'Error with token' });
      }

      try {
        const hashedPassword = await bcrypt.hash(password, 10);

        await db.collection("users").updateOne({ token }, {
          $set: {
            password: hashedPassword,
           
            confirmPassword: hashedPassword
          }
        });

        console.log('Password changed successfully.');
        res.json({ message: 'Password changed successfully' });
      } catch (error) {
        console.error('Failed to reset password:', error);
        res.status(500).json({ message: 'Failed to reset password' });
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});