const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
require('dotenv').config();
const multer = require('multer');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');

// Import models - ONLY import them, don't define them again
const User = require('./models/User');
const Message = require('./models/Message');
const FriendRequest = require('./models/FriendRequest');

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Configure Mongoose
mongoose.set('strictQuery', false);

// MongoDB Connection with better error handling
const connectDB = async () => {
    try {
        console.log('Attempting to connect to MongoDB...');
        
        if (!process.env.MONGODB_URI) {
            throw new Error('MongoDB URI is not defined in environment variables');
        }

        await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 5000,
            family: 4
        });

        console.log('MongoDB Connected Successfully');
        
        // Create a test user to verify database access
        try {
            const testUser = await User.findOne({ email: 'test@test.com' });
            if (!testUser) {
                const newTestUser = new User({
                    fullName: 'Test User',
                    username: 'testuser',
                    email: 'test@test.com',
                    password: await bcrypt.hash('password123', 10)
                });
                await newTestUser.save();
                console.log('Test user created successfully');
            } else {
                console.log('Test user already exists');
            }
        } catch (userError) {
            console.log('Test user operation error:', userError.message);
        }

        startServer();
    } catch (error) {
        console.error('MongoDB Connection Error Details:', {
            message: error.message,
            code: error.code,
            name: error.name
        });
        
        if (error.name === 'MongoServerSelectionError') {
            console.log('Could not connect to MongoDB server. Please check:');
            console.log('1. Network connectivity');
            console.log('2. MongoDB Atlas status');
            console.log('3. IP Whitelist settings');
        }
        
        if (error.name === 'MongoError' && error.code === 18) {
            console.log('Authentication failed. Please check:');
            console.log('1. Username is correct');
            console.log('2. Password is correct');
            console.log('3. User has correct database access');
        }
    }
};

// Server Initialization
const startServer = () => {
    const server = http.createServer(app);
    
    // Socket.IO setup
    const io = socketIo(server, {
        cors: {
            origin: "*",
            methods: ["GET", "POST"]
        }
    });

    // Socket.IO connection handling
    io.on('connection', (socket) => {
        console.log('User connected:', socket.id);

        socket.on('join', (userId) => {
            socket.join(userId);
            console.log('User joined room:', userId);
        });

        socket.on('sendMessage', async (data) => {
            try {
                const { senderId, receiverId, message } = data;
                
                // Save message using imported Message model
                const newMessage = new Message({
                    sender: senderId,
                    receiver: receiverId,
                    message: message
                });
                await newMessage.save();

                // Send message to receiver
                io.to(receiverId).emit('newMessage', {
                    sender: senderId,
                    message: message,
                    timestamp: new Date()
                });
            } catch (error) {
                console.error('Message error:', error);
            }
        });

        socket.on('disconnect', () => {
            console.log('User disconnected:', socket.id);
        });
    });

    server.listen(port, () => {
        console.log(`Server running on port ${port}`);
    });
};

// Test route
app.get('/test', async (req, res) => {
    try {
        // Test database read operation
        const users = await User.find().limit(1);
        res.json({ 
            message: 'Test successful',
            dbConnection: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
            usersFound: users.length
        });
    } catch (error) {
        res.status(500).json({ 
            error: error.message,
            dbState: mongoose.connection.readyState
        });
    }
});

// Initialize connection
connectDB();

// Basic test route
app.get('/', (req, res) => {
    res.json({ message: 'Server is running' });
});

// Basic Routes
app.get('/api/status', (req, res) => {
    try {
        const dbState = mongoose.connection.readyState;
        res.json({
            status: 'ok',
            server: 'running',
            database: dbState === 1 ? 'connected' : 'disconnected'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Username generator function
async function generateUsername(fullName) {
    // Convert full name to lowercase and remove special characters
    const base = fullName.toLowerCase().replace(/[^a-z0-9]/g, '');
    let username = base;
    let counter = 1;
    
    // Keep trying until we find a unique username
    while (await User.findOne({ username })) {
        username = `${base}${counter}`;
        counter++;
    }
    
    return username;
}

// Routes
app.post('/api/signup', async (req, res) => {
    try {
        const { fullName, username, email, password } = req.body;

        // Validate input
        if (!fullName || !username || !email || !password) {
            return res.status(400).json({ 
                error: 'All fields are required' 
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ 
            $or: [{ email }, { username }] 
        });

        if (existingUser) {
            return res.status(400).json({ 
                error: existingUser.email === email 
                    ? 'Email already registered' 
                    : 'Username already taken'
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user with default location
        const user = new User({
            fullName,
            username,
            email,
            password: hashedPassword,
            skills: [],
            location: {
                type: 'Point',
                coordinates: [0, 0] // Default coordinates
            }
        });

        await user.save();
        
        console.log('User created successfully:', {
            id: user._id,
            fullName: user.fullName,
            username: user.username,
            email: user.email
        });

        res.status(201).json({ 
            message: 'User created successfully',
            userId: user._id 
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ 
            error: error.message || 'Failed to create user' 
        });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Send back complete user data
        res.json({
            id: user._id,
            fullName: user.fullName,
            username: user.username,
            email: user.email,
            skills: user.skills || []
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Update the users endpoint to return all users
app.get('/api/users', async (req, res) => {
    try {
        const users = await User.find({}, { password: 0 });
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// Add connection routes
app.post('/api/connect', async (req, res) => {
    try {
        const { userId, targetUsername } = req.body;
        
        const user = await User.findById(userId);
        const targetUser = await User.findOne({ username: targetUsername });
        
        if (!targetUser) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        if (user.connections.includes(targetUser._id)) {
            return res.status(400).json({ error: 'Already connected' });
        }
        
        if (user.pendingConnections.includes(targetUser._id)) {
            return res.status(400).json({ error: 'Connection request already sent' });
        }
        
        targetUser.pendingConnections.push(user._id);
        await targetUser.save();
        
        res.json({ message: 'Connection request sent' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to send connection request' });
    }
});

app.get('/api/connections/:userId', async (req, res) => {
    try {
        const user = await User.findById(req.params.userId)
            .populate('connections', 'fullName username email')
            .populate('pendingConnections', 'fullName username email');
            
        res.json({
            connections: user.connections,
            pendingConnections: user.pendingConnections
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch connections' });
    }
});

app.post('/api/accept-connection', async (req, res) => {
    try {
        const { userId, requesterId } = req.body;
        
        const user = await User.findById(userId);
        const requester = await User.findById(requesterId);
        
        user.pendingConnections = user.pendingConnections.filter(id => !id.equals(requesterId));
        user.connections.push(requesterId);
        requester.connections.push(userId);
        
        await user.save();
        await requester.save();
        
        res.json({ message: 'Connection accepted' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to accept connection' });
    }
});

// Add this endpoint for username availability check
app.post('/api/check-username', async (req, res) => {
    try {
        const { username } = req.body;
        console.log('Checking username:', username);
        
        if (!username) {
            return res.status(400).json({ error: 'Username is required' });
        }

        const existingUser = await User.findOne({ username: username });
        console.log('Existing user:', existingUser);
        
        res.json({ available: !existingUser });
    } catch (error) {
        console.error('Username check error:', error);
        res.status(500).json({ error: 'Failed to check username' });
    }
});

// Move this line to the top with other middleware
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Update the multer storage configuration
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, 'uploads/'))
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
        cb(null, uniqueSuffix + path.extname(file.originalname))
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Not an image! Please upload an image.'));
        }
    }
});

// Update the profile update route
app.post('/api/update-profile', upload.single('avatar'), async (req, res) => {
    try {
        const { userId, fullName, skills } = req.body;
        
        const updateData = {
            fullName,
            skills: JSON.parse(skills || '[]')
        };

        if (req.file) {
            const avatarUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
            updateData.avatarUrl = avatarUrl;
        }

        const user = await User.findByIdAndUpdate(
            userId,
            updateData,
            { new: true }
        );

        res.json({
            fullName: user.fullName,
            avatarUrl: user.avatarUrl,
            skills: user.skills,
            email: user.email,
            username: user.username
        });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// Add error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({
        status: 'error',
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// Add this after your User model definition
async function createAdminUser() {
    try {
        // Check if admin already exists
        const adminExists = await User.findOne({ email: 'admin@codersmeet.com' });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            const admin = new User({
                fullName: 'Admin',
                email: 'admin@codersmeet.com',
                password: hashedPassword,
                isAdmin: true
            });
            await admin.save();
            console.log('Admin user created successfully');
        }
    } catch (error) {
        console.error('Error creating admin:', error);
    }
}

// Call this when your server starts
createAdminUser();

// Add this after middleware setup
app.use('/uploads', express.static('uploads'));

// Update the user data endpoint
app.get('/api/user/:username', async (req, res) => {
    try {
        const username = req.params.username;
        console.log('Fetching user data for:', username);
        
        const user = await User.findOne({ username: username });
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Send user data
        res.json({
            id: user._id,
            fullName: user.fullName,
            username: user.username,
            email: user.email,
            bio: user.bio || '',
            avatarUrl: user.avatarUrl,
            skills: user.skills || []
        });

    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({ error: 'Failed to fetch user data' });
    }
});

// Add this route to your server.js
app.get('/api/current-user', async (req, res) => {
    try {
        const userId = req.query.userId;
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({
            id: user._id,
            fullName: user.fullName,
            username: user.username,
            email: user.email,
            skills: user.skills || []
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch user data' });
    }
});

// Message routes - use the imported Message model
app.get('/api/messages/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const { with: withUserId } = req.query;

        const messages = await Message.find({
            $or: [
                { sender: userId, receiver: withUserId },
                { sender: withUserId, receiver: userId }
            ]
        })
        .sort({ timestamp: 1 })
        .populate('sender', 'fullName username')
        .populate('receiver', 'fullName username');

        res.json(messages);
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ error: 'Failed to fetch messages' });
    }
});

// Search users by username
app.get('/api/users/search', async (req, res) => {
    try {
        const { query, userId } = req.query;
        if (!query) return res.json([]);

        const users = await User.find({
            _id: { $ne: userId },
            username: new RegExp(query, 'i'),
            isAdmin: { $ne: true }
        }, {
            fullName: 1,
            username: 1,
            _id: 1
        }).limit(10);

        res.json(users);
    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ error: 'Search failed' });
    }
});

// Update user location
app.post('/api/users/location', async (req, res) => {
    try {
        const { userId, latitude, longitude } = req.body;
        
        await User.findByIdAndUpdate(userId, {
            location: {
                type: 'Point',
                coordinates: [longitude, latitude]
            },
            lastActive: new Date()
        });

        res.json({ message: 'Location updated' });
    } catch (error) {
        console.error('Location update error:', error);
        res.status(500).json({ error: 'Failed to update location' });
    }
});

// Get nearby users
app.get('/api/users/nearby', async (req, res) => {
    try {
        const { userId, latitude, longitude } = req.query;
        const ranges = [10, 20, 30, 50, 100, 500, 1000]; // kilometers
        
        let results = [];
        for (let range of ranges) {
            const users = await User.find({
                _id: { $ne: userId },
                location: {
                    $near: {
                        $geometry: {
                            type: 'Point',
                            coordinates: [parseFloat(longitude), parseFloat(latitude)]
                        },
                        $maxDistance: range * 1000 // convert to meters
                    }
                }
            }, {
                fullName: 1,
                username: 1,
                _id: 1,
                location: 1
            }).limit(50);

            if (users.length > 0) {
                results.push({
                    range: range,
                    users: users.map(user => ({
                        ...user.toObject(),
                        distance: getDistance(
                            latitude, 
                            longitude, 
                            user.location.coordinates[1],
                            user.location.coordinates[0]
                        )
                    }))
                });
            }
        }

        res.json(results);
    } catch (error) {
        console.error('Nearby search error:', error);
        res.status(500).json({ error: 'Failed to find nearby users' });
    }
});

// Send friend request
app.post('/api/friend-request', async (req, res) => {
    try {
        const { senderId, receiverId } = req.body;

        // Check if request already exists
        const existingRequest = await FriendRequest.findOne({
            $or: [
                { sender: senderId, receiver: receiverId },
                { sender: receiverId, receiver: senderId }
            ]
        });

        if (existingRequest) {
            return res.status(400).json({ error: 'Friend request already exists' });
        }

        const request = new FriendRequest({
            sender: senderId,
            receiver: receiverId
        });

        await request.save();
        res.json({ message: 'Friend request sent' });
    } catch (error) {
        console.error('Friend request error:', error);
        res.status(500).json({ error: 'Failed to send friend request' });
    }
});

// Helper function to calculate distance
function getDistance(lat1, lon1, lat2, lon2) {
    const R = 6371; // Earth's radius in km
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = 
        Math.sin(dLat/2) * Math.sin(dLat/2) +
        Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
        Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return Math.round(R * c);
}

// Error handling
process.on('unhandledRejection', (error) => {
    console.error('Unhandled Rejection:', error);
});

process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    process.exit(1);
});

// Admin creation route (keep this route secure or remove after creating admin)
app.post('/api/create-admin', async (req, res) => {
    try {
        const adminUser = new User({
            fullName: "Admin User",
            username: "admin",
            email: "admin@codersmeet.com",
            password: await bcrypt.hash("Admin@123", 10),
            isAdmin: true,
            location: {
                type: 'Point',
                coordinates: [0, 0]
            }
        });

        await adminUser.save();
        res.json({ message: 'Admin user created successfully' });
    } catch (error) {
        console.error('Admin creation error:', error);
        res.status(500).json({ error: error.message });
    }
});

module.exports = app; 