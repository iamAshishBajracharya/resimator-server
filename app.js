require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const cors = require('cors');

const app = express();
app.use(bodyParser.json());


app.use(cors());

// Environment variables
const PORT = process.env.PORT || 9000; // Default to 9000 if PORT is not defined
const SECRET_KEY = process.env.SECRET_KEY || 'default_secret_key';

// Load data from JSON file
const dataPath = 'data.json';
const loadData = () => JSON.parse(fs.readFileSync(dataPath, 'utf-8'));
const saveData = (data) => fs.writeFileSync(dataPath, JSON.stringify(data, null, 2));

// Middleware for token verification
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Access token missing' });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Middleware for role-based access
const roleBasedAccess = (roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ error: 'Forbidden: Access denied' });
  }
  next();
};

// Configure multer for file uploads with timestamped file names
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Directory to store uploaded files
  },
  filename: (req, file, cb) => {
    const timestamp = Date.now(); // Current timestamp
    const ext = path.extname(file.originalname); // File extension (e.g., .jpg, .png)
    const originalName = path.basename(file.originalname, ext); // Original file name without extension
    cb(null, `${originalName}-${timestamp}${ext}`); // Append timestamp to the file name
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // Limit file size to 2MB
  fileFilter: (req, file, cb) => {
    const fileTypes = /jpeg|jpg|png/;
    const extname = fileTypes.test(path.extname(file.originalname).toLowerCase());
    const mimeType = fileTypes.test(file.mimetype);
    if (extname && mimeType) {
      return cb(null, true);
    } else {
      cb(new Error('Only .jpg, .jpeg, or .png files are allowed!'));
    }
  }
});

// Authentication route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const data = loadData();

  const user = data.users.find((u) => u.email === email);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  if (!user.isActive) {
    return res.status(403).json({ error: 'User account is inactive' });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ message: 'Authentication successful', token,
    user: {
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      role: user.role,
      profileImage: user.profileImage, // Optional, if available
    }
   });
});

// Route to create a new user with hashed password and file upload
app.post('/api/signup', upload.single('profileImage'), async (req, res) => {
  try {
    const {
      fullName,
      username,
      email,
      phoneNumber,
      socialSecurityNo,
      gender,
      dateOfBirth,
      status,
      role,
      skipFTN,
      sendWelcomeEmail,
      country,
      state,
      city,
      postalCode,
      streetAddress,
      residentialArea,
      invoicingAddressEnabled,
      password // Add password here
    } = req.body;

    const profileImage = req.file ? req.file.filename : null; // Get the uploaded file's name

    // Hash the password before saving
    const hashedPassword = await bcrypt.hash(password, 10); // 10 is the salt rounds

    const data = loadData();

    const newUser = {
      id: data.users.length + 1, // Auto-generate a unique ID
      fullName,
      username,
      email,
      phoneNumber,
      socialSecurityNo,
      gender,
      dateOfBirth,
      status,
      role,
      skipFTN: skipFTN === 'true',
      sendWelcomeEmail: sendWelcomeEmail === 'true',
      profileImage,
      password: hashedPassword, // Save hashed password
      address: {
        country,
        state,
        city,
        postalCode,
        streetAddress,
        residentialArea,
        invoicingAddressEnabled: invoicingAddressEnabled === 'true'
      }
    };

    data.users.push(newUser);
    saveData(data);

    res.status(201).json({
      message: 'User created successfully',
      user: newUser
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// Protected routes (examples)
app.get('/api/admin/metrics', verifyToken, roleBasedAccess(['admin']), (req, res) => {
  const data = loadData();
  res.json(data.adminMetrics);
});

app.get('/api/user/tasks', verifyToken, roleBasedAccess(['user']), (req, res) => {
  const data = loadData();
  res.json(data.userTasks);
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
