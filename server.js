const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
require('dotenv').config();


const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key_here';

// Middleware
// Replace your current CORS middleware with this:
// Replace the CORS configuration with:
app.use(cors({
    origin: [
        'https://project-24-alpha.vercel.app',
        'https://projectdhaara.vercel.app',
        'http://localhost:5000',
        'http://localhost:5173'
    ],
    credentials: true
}));
app.use(express.json());
app.use(express.static('public'));
app.use(express.static(path.join(__dirname, 'dist')));


const API_BASE_URL = window.location.hostname === 'localhost' 
  ? 'http://localhost:5000' 
  : 'https://project-24-alpha.vercel.app/';

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/projectflow';
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    role: {
        type: String,
        enum: ['student', 'admin'],
        default: 'student'
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastLogin: {
        type: Date,
        default: Date.now
    }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Login History Schema
const loginHistorySchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    timestamp: {
        type: Date,
        default: Date.now
    },
    userAgent: String,
    ipAddress: String
});

const LoginHistory = mongoose.model('LoginHistory', loginHistorySchema);

// Project Schema
const projectSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        trim: true
    },
    description: {
        type: String,
        required: true
    },
    status: {
        type: String,
        enum: ['active', 'upcoming', 'completed'],
        default: 'active'
    },
    startDate: {
        type: Date,
        required: true
    },
    endDate: {
        type: Date,
        required: true
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

projectSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

const Project = mongoose.model('Project', projectSchema);

// Application Schema
const applicationSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    projectId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Project',
        required: true
    },
    status: {
        type: String,
        enum: ['pending', 'approved', 'rejected'],
        default: 'pending'
    },
    message: {
        type: String,
        trim: true
    },
    appliedAt: {
        type: Date,
        default: Date.now
    },
    reviewedAt: {
        type: Date
    },
    reviewedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }
});

const Application = mongoose.model('Application', applicationSchema);

// Group Schema
const groupSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    projectId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Project',
        required: true
    },
    members: [{
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true
        },
        role: {
            type: String,
            enum: ['leader', 'member'],
            default: 'member'
        },
        joinedAt: {
            type: Date,
            default: Date.now
        }
    }],
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const Group = mongoose.model('Group', groupSchema);

// Submission Schema
const submissionSchema = new mongoose.Schema({
    groupId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Group',
        required: true
    },
    projectId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Project',
        required: true
    },
    title: {
        type: String,
        required: true,
        trim: true
    },
    description: {
        type: String
    },
    files: [{
        filename: String,
        originalName: String,
        path: String,
        uploadedAt: {
            type: Date,
            default: Date.now
        }
    }],
    submittedAt: {
        type: Date,
        default: Date.now
    },
    status: {
        type: String,
        enum: ['submitted', 'in progress', 'graded'],
        default: 'submitted'
    }
});

const Submission = mongoose.model('Submission', submissionSchema);

// Grade Schema
const gradeSchema = new mongoose.Schema({
    submissionId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Submission',
        required: true
    },
    groupId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Group',
        required: true
    },
    projectId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Project',
        required: true
    },
    grade: {
        type: Number,
        required: true,
        min: 0,
        max: 100
    },
    feedback: {
        type: String,
        trim: true
    },
    gradedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    gradedAt: {
        type: Date,
        default: Date.now
    }
});

const Grade = mongoose.model('Grade', gradeSchema);

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Middleware to check if user is admin
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied. Admin required.' });
    }
    next();
};

// Routes

// Serve the login/signup page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, "login.html"));
});

app.get('/user-dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, "user-dashboard.html"));
});

app.get('/admin-dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, "admin-dashboard.html"));
});

app.get('/chatbot', (req, res) => {
    res.sendFile(path.join(__dirname, "chatbot.html"));
});

// User registration
app.post(`${API_BASE_URL}/api/signup`, async (req, res) => {
    try {
        const { name, email, password, role } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists with this email' });
        }

        // Create new user
        const newUser = new User({
            name,
            email,
            password,
            role: role || 'student'
        });

        await newUser.save();

        // Generate JWT token
        const token = jwt.sign(
            { userId: newUser._id, email: newUser.email, role: newUser.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            message: 'User created successfully',
            token,
            user: {
                id: newUser._id,
                name: newUser.name,
                email: newUser.email,
                role: newUser.role
            }
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Error creating user', error: error.message });
    }
});

// User login
app.post(`${API_BASE_URL}/api/login`, async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        // Check password
        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        // Update last login
        user.lastLogin = Date.now();
        await user.save();

        // Record login history
        const loginHistory = new LoginHistory({
            userId: user._id,
            userAgent: req.get('User-Agent'),
            ipAddress: req.ip || req.connection.remoteAddress
        });
        await loginHistory.save();

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Redirect based on role
        let redirectUrl = user.role === 'admin' ? '/admin-dashboard.html' : '/user-dashboard.html';

        res.json({
            message: 'Login successful',
            token,
            redirectUrl,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Error during login', error: error.message });
    }
});

// Forgot password (simplified version)
app.post(`${API_BASE_URL}/api/forgot-password`, async (req, res) => {
    try {
        const { email } = req.body;
        
        // Check if user exists
        const user = await User.findOne({ email });
        if (!user) {
            // For security reasons, don't reveal if email exists or not
            return res.json({ message: 'If the email exists, a password reset link has been sent' });
        }

        // In a real application, you would:
        // 1. Generate a password reset token
        // 2. Save it to the user document with an expiration time
        // 3. Send an email with a reset link
        
        // For now, we'll just simulate this process
        res.json({ message: 'If the email exists, a password reset link has been sent' });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ message: 'Error processing request', error: error.message });
    }
});

// Get user profile (protected route)
app.get(`${API_BASE_URL}/api/profile`, authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        res.json({ user });
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ message: 'Error fetching profile', error: error.message });
    }
});

// Get login history (protected route)
app.get(`${API_BASE_URL}/api/login-history`, authenticateToken, async (req, res) => {
    try {
        const history = await LoginHistory.find({ userId: req.user.userId })
            .sort({ timestamp: -1 })
            .limit(10);
        
        res.json({ history });
    } catch (error) {
        console.error('Login history error:', error);
        res.status(500).json({ message: 'Error fetching login history', error: error.message });
    }
});

// Get all users (admin only)
app.get(`${API_BASE_URL}/api/users`, authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await User.find().select('-password').sort({ createdAt: -1 });
        res.json({ users });
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ message: 'Error fetching users', error: error.message });
    }
});

// Project routes (admin only)
app.get(`${API_BASE_URL}/api/projects`, authenticateToken, async (req, res) => {
    try {
        const projects = await Project.find().populate('createdBy', 'name email');
        res.json({ projects });
    } catch (error) {
        console.error('Get projects error:', error);
        res.status(500).json({ message: 'Error fetching projects', error: error.message });
    }
});

app.post(`${API_BASE_URL}/api/projects`, authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { title, description, status, startDate, endDate } = req.body;
        
        const project = new Project({
            title,
            description,
            status,
            startDate,
            endDate,
            createdBy: req.user.userId
        });
        
        await project.save();
        await project.populate('createdBy', 'name email');
        
        res.status(201).json({ message: 'Project created successfully', project });
    } catch (error) {
        console.error('Create project error:', error);
        res.status(500).json({ message: 'Error creating project', error: error.message });
    }
});

app.put(`${API_BASE_URL}/api/projects/:id`, authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { title, description, status, startDate, endDate } = req.body;
        
        const project = await Project.findByIdAndUpdate(
            req.params.id,
            { title, description, status, startDate, endDate },
            { new: true, runValidators: true }
        ).populate('createdBy', 'name email');
        
        if (!project) {
            return res.status(404).json({ message: 'Project not found' });
        }
        
        res.json({ message: 'Project updated successfully', project });
    } catch (error) {
        console.error('Update project error:', error);
        res.status(500).json({ message: 'Error updating project', error: error.message });
    }
});

app.delete(`${API_BASE_URL}/api/projects/:id`, authenticateToken, requireAdmin, async (req, res) => {
    try {
        const project = await Project.findByIdAndDelete(req.params.id);
        
        if (!project) {
            return res.status(404).json({ message: 'Project not found' });
        }
        
        // Also delete related applications, groups, submissions, and grades
        await Application.deleteMany({ projectId: req.params.id });
        await Group.deleteMany({ projectId: req.params.id });
        await Submission.deleteMany({ projectId: req.params.id });
        await Grade.deleteMany({ projectId: req.params.id });
        
        res.json({ message: 'Project deleted successfully' });
    } catch (error) {
        console.error('Delete project error:', error);
        res.status(500).json({ message: 'Error deleting project', error: error.message });
    }
});

// Application routes
app.get(`${API_BASE_URL}/api/applications`, authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status } = req.query;
        let filter = {};
        
        if (status) {
            filter.status = status;
        }
        
        const applications = await Application.find(filter)
            .populate('userId', 'name email')
            .populate('projectId', 'title')
            .populate('reviewedBy', 'name')
            .sort({ appliedAt: -1 });
        
        res.json({ applications });
    } catch (error) {
        console.error('Get applications error:', error);
        res.status(500).json({ message: 'Error fetching applications', error: error.message });
    }
});

app.put(`${API_BASE_URL}/api/applications/:id/review`, authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        
        const application = await Application.findByIdAndUpdate(
            req.params.id,
            { 
                status, 
                reviewedAt: Date.now(), 
                reviewedBy: req.user.userId 
            },
            { new: true, runValidators: true }
        )
        .populate('userId', 'name email')
        .populate('projectId', 'title')
        .populate('reviewedBy', 'name');
        
        if (!application) {
            return res.status(404).json({ message: 'Application not found' });
        }
        
        res.json({ message: 'Application reviewed successfully', application });
    } catch (error) {
        console.error('Review application error:', error);
        res.status(500).json({ message: 'Error reviewing application', error: error.message });
    }
});

// Group routes
app.get(`${API_BASE_URL}/api/groups`, authenticateToken, async (req, res) => {
    try {
        const groups = await Group.find()
            .populate('projectId', 'title')
            .populate('members.userId', 'name email')
            .populate('createdBy', 'name')
            .sort({ createdAt: -1 });
        
        res.json({ groups });
    } catch (error) {
        console.error('Get groups error:', error);
        res.status(500).json({ message: 'Error fetching groups', error: error.message });
    }
});

app.post(`${API_BASE_URL}/api/groups/generate`, authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { projectId, groupSize } = req.body;
        
        // Get approved applications for this project
        const applications = await Application.find({ 
            projectId, 
            status: 'approved' 
        }).populate('userId', 'name email');
        
        if (applications.length === 0) {
            return res.status(400).json({ message: 'No approved applications for this project' });
        }
        
        // Shuffle applications randomly
        const shuffledApplications = applications.sort(() => 0.5 - Math.random());
        
        // Generate group names
        const groupNames = [
            'Data Warriors', 'AI Innovators', 'Web Developers', 'Cloud Masters',
            'Mobile Creators', 'Tech Titans', 'Code Crusaders', 'Digital Dynamos',
            'Byte Brigade', 'Pixel Pioneers', 'Logic Legends', 'Algorithm Avengers'
        ];
        
        const groups = [];
        const membersPerGroup = parseInt(groupSize) || 4;
        
        // Create groups
        for (let i = 0; i < shuffledApplications.length; i += membersPerGroup) {
            const groupApplications = shuffledApplications.slice(i, i + membersPerGroup);
            
            if (groupApplications.length > 0) {
                const groupName = groupNames[groups.length % groupNames.length] + ' ' + (groups.length + 1);
                
                const group = new Group({
                    name: groupName,
                    projectId,
                    members: groupApplications.map((app, index) => ({
                        userId: app.userId._id,
                        role: index === 0 ? 'leader' : 'member'
                    })),
                    createdBy: req.user.userId
                });
                
                await group.save();
                await group.populate('members.userId', 'name email');
                await group.populate('projectId', 'title');
                
                groups.push(group);
            }
        }
        
        res.json({ message: 'Groups generated successfully', groups });
    } catch (error) {
        console.error('Generate groups error:', error);
        res.status(500).json({ message: 'Error generating groups', error: error.message });
    }
});

// Submission routes
app.get('/api/submissions', authenticateToken, async (req, res) => {
    try {
        const submissions = await Submission.find()
            .populate('groupId', 'name')
            .populate('projectId', 'title')
            .sort({ submittedAt: -1 });
        
        res.json({ submissions });
    } catch (error) {
        console.error('Get submissions error:', error);
        res.status(500).json({ message: 'Error fetching submissions', error: error.message });
    }
});

// Grade routes
app.get('/api/grades', authenticateToken, async (req, res) => {
    try {
        const grades = await Grade.find()
            .populate('submissionId')
            .populate('groupId', 'name')
            .populate('projectId', 'title')
            .populate('gradedBy', 'name')
            .sort({ gradedAt: -1 });
        
        res.json({ grades });
    } catch (error) {
        console.error('Get grades error:', error);
        res.status(500).json({ message: 'Error fetching grades', error: error.message });
    }
});

app.post('/api/grades', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { submissionId, groupId, projectId, grade, feedback } = req.body;
        
        const newGrade = new Grade({
            submissionId,
            groupId,
            projectId,
            grade,
            feedback,
            gradedBy: req.user.userId
        });
        
        await newGrade.save();
        
        // Update submission status to graded
        await Submission.findByIdAndUpdate(submissionId, { status: 'graded' });
        
        await newGrade.populate('groupId', 'name');
        await newGrade.populate('projectId', 'title');
        await newGrade.populate('gradedBy', 'name');
        
        res.status(201).json({ message: 'Grade submitted successfully', grade: newGrade });
    } catch (error) {
        console.error('Create grade error:', error);
        res.status(500).json({ message: 'Error submitting grade', error: error.message });
    }
});

// Dashboard stats (admin only)
app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const activeProjects = await Project.countDocuments({ status: 'active' });
        const totalUsers = await User.countDocuments();
        const pendingApplications = await Application.countDocuments({ status: 'pending' });
        const submissionsToReview = await Submission.countDocuments({ status: 'submitted' });
        
        res.json({
            activeProjects,
            totalUsers,
            pendingApplications,
            submissionsToReview
        });
    } catch (error) {
        console.error('Get admin stats error:', error);
        res.status(500).json({ message: 'Error fetching admin stats', error: error.message });
    }
});

// Leaderboard data
app.get('/api/leaderboard', async (req, res) => {
    try {
        const grades = await Grade.find()
            .populate('groupId', 'name')
            .populate('projectId', 'title')
            .sort({ grade: -1 });
        
        res.json({ leaderboard: grades });
    } catch (error) {
        console.error('Get leaderboard error:', error);
        res.status(500).json({ message: 'Error fetching leaderboard', error: error.message });
    }
});



// Add these routes before the server startup section

// Get user's applications
app.get('/api/user/applications', authenticateToken, async (req, res) => {
    try {
        const applications = await Application.find({ userId: req.user.userId })
            .populate('projectId', 'title description status startDate endDate')
            .sort({ appliedAt: -1 });
        
        res.json({ applications });
    } catch (error) {
        console.error('Get user applications error:', error);
        res.status(500).json({ message: 'Error fetching applications', error: error.message });
    }
});

// Submit application
app.post('/api/applications', authenticateToken, async (req, res) => {
    try {
        const { projectId, message } = req.body;
        
        // Check if user already applied to this project
        const existingApplication = await Application.findOne({
            userId: req.user.userId,
            projectId
        });
        
        if (existingApplication) {
            return res.status(400).json({ message: 'You have already applied to this project' });
        }
        
        const application = new Application({
            userId: req.user.userId,
            projectId,
            message,
            status: 'pending'
        });
        
        await application.save();
        await application.populate('projectId', 'title');
        
        res.status(201).json({ 
            message: 'Application submitted successfully', 
            application 
        });
    } catch (error) {
        console.error('Submit application error:', error);
        res.status(500).json({ message: 'Error submitting application', error: error.message });
    }
});

// Get user's group information
app.get('/api/user/group', authenticateToken, async (req, res) => {
    try {
        const group = await Group.findOne({ 
            'members.userId': req.user.userId 
        })
        .populate('projectId', 'title description')
        .populate('members.userId', 'name email')
        .populate('createdBy', 'name');
        
        if (!group) {
            return res.status(404).json({ message: 'No group found' });
        }
        
        res.json({ group });
    } catch (error) {
        console.error('Get user group error:', error);
        res.status(500).json({ message: 'Error fetching group information', error: error.message });
    }
});

// Get user's notifications
app.get('/api/user/notifications', authenticateToken, async (req, res) => {
    try {
        const notifications = await Notification.find({ 
            userId: req.user.userId 
        }).sort({ createdAt: -1 });
        
        res.json({ notifications });
    } catch (error) {
        console.error('Get notifications error:', error);
        res.status(500).json({ message: 'Error fetching notifications', error: error.message });
    }
});

// Mark notification as read
app.patch('/api/notifications/:id/read', authenticateToken, async (req, res) => {
    try {
        const notification = await Notification.findOneAndUpdate(
            { 
                _id: req.params.id, 
                userId: req.user.userId 
            },
            { read: true },
            { new: true }
        );
        
        if (!notification) {
            return res.status(404).json({ message: 'Notification not found' });
        }
        
        res.json({ message: 'Notification marked as read', notification });
    } catch (error) {
        console.error('Mark notification read error:', error);
        res.status(500).json({ message: 'Error updating notification', error: error.message });
    }
});

// Mark all notifications as read
app.patch('/api/notifications/read-all', authenticateToken, async (req, res) => {
    try {
        await Notification.updateMany(
            { 
                userId: req.user.userId,
                read: false 
            },
            { read: true }
        );
        
        res.json({ message: 'All notifications marked as read' });
    } catch (error) {
        console.error('Mark all notifications read error:', error);
        res.status(500).json({ message: 'Error updating notifications', error: error.message });
    }
});


// Get single submission
app.get('/api/submissions/:id', authenticateToken, async (req, res) => {
    try {
        const submission = await Submission.findById(req.params.id)
            .populate('groupId', 'name')
            .populate('projectId', 'title');
        
        if (!submission) {
            return res.status(404).json({ message: 'Submission not found' });
        }
        
        res.json(submission);
    } catch (error) {
        console.error('Get submission error:', error);
        res.status(500).json({ message: 'Error fetching submission', error: error.message });
    }
});


// Get single application by ID
app.get('/api/applications/:id', authenticateToken, async (req, res) => {
    try {
        const application = await Application.findById(req.params.id)
            .populate('projectId', 'title')   // get project title
            .populate('userId', 'name email') // get applicant details
            .populate('reviewedBy', 'name');  // get reviewer name if available

        if (!application) {
            return res.status(404).json({ message: 'Application not found' });
        }

        res.json({ application });
    } catch (error) {
        console.error('Get application error:', error);
        res.status(500).json({ message: 'Error fetching application', error: error.message });
    }
});


// Submit project work
app.post('/api/submissions', authenticateToken, async (req, res) => {
    try {
        const { driveLink, notes } = req.body;
        
        // Check if user is in a group
        const group = await Group.findOne({ 
            'members.userId': req.user.userId 
        }).populate('projectId', 'title');
        
        if (!group) {
            return res.status(400).json({ message: 'You need to be in a group to submit work' });
        }
        
        // Check if submission already exists for this group and project
        const existingSubmission = await Submission.findOne({
            groupId: group._id,
            projectId: group.projectId._id
        });
        
        if (existingSubmission) {
            return res.status(400).json({ message: 'Your group has already submitted this project' });
        }
        
        const submission = new Submission({
            groupId: group._id,
            projectId: group.projectId._id,
            title: `${group.name} - ${group.projectId.title} Submission`,
            description: notes,
            files: [{
                filename: 'drive-link',
                originalName: 'Google Drive Submission',
                path: driveLink
            }],
            status: 'submitted'
        });
        
        await submission.save();
        
        // Create notification for admin
        const adminNotification = new Notification({
            userId: req.user.userId, // This would ideally be sent to admins
            title: 'New Project Submission',
            message: `Group ${group.name} has submitted their project: ${group.projectId.title}`,
            type: 'submission'
        });
        
        await adminNotification.save();
        
        res.status(201).json({ 
            message: 'Project submitted successfully', 
            submission 
        });
    } catch (error) {
        console.error('Submit project error:', error);
        res.status(500).json({ message: 'Error submitting project', error: error.message });
    }
});

// Get user dashboard stats
app.get('/api/user/stats', authenticateToken, async (req, res) => {
    try {
        const applications = await Application.countDocuments({ userId: req.user.userId });
        const approvedApplications = await Application.countDocuments({ 
            userId: req.user.userId, 
            status: 'approved' 
        });
        
        const group = await Group.findOne({ 
            'members.userId': req.user.userId 
        });
        const groupMembers = group ? group.members.length : 0;
        
        const submissions = await Submission.countDocuments({ 
            groupId: group ? group._id : null 
        });
        
        res.json({
            applied: applications,
            approved: approvedApplications,
            groupMembers,
            submitted: submissions
        });
    } catch (error) {
        console.error('Get user stats error:', error);
        res.status(500).json({ message: 'Error fetching user stats', error: error.message });
    }
});

// Add Notification Schema (add this with the other schemas)
const notificationSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    title: {
        type: String,
        required: true,
        trim: true
    },
    message: {
        type: String,
        required: true
    },
    type: {
        type: String,
        enum: ['application', 'group', 'submission', 'grade', 'system'],
        default: 'system'
    },
    read: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const Notification = mongoose.model('Notification', notificationSchema);

// Add this middleware to create notifications when applications are reviewed
app.put('/api/applications/:id/review', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        
        const application = await Application.findByIdAndUpdate(
            req.params.id,
            { 
                status, 
                reviewedAt: Date.now(), 
                reviewedBy: req.user.userId 
            },
            { new: true, runValidators: true }
        )
        .populate('userId', 'name email')
        .populate('projectId', 'title')
        .populate('reviewedBy', 'name');
        
        if (!application) {
            return res.status(404).json({ message: 'Application not found' });
        }
        
        // Create notification for user
        const notification = new Notification({
            userId: application.userId._id,
            title: 'Application Update',
            message: `Your application for "${application.projectId.title}" has been ${status}`,
            type: 'application'
        });
        
        await notification.save();
        
        res.json({ message: 'Application reviewed successfully', application });
    } catch (error) {
        console.error('Review application error:', error);
        res.status(500).json({ message: 'Error reviewing application', error: error.message });
    }
});

// Add this middleware to create notifications when groups are created
app.post('/api/groups/generate', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { projectId, groupSize } = req.body;
        
        // Get approved applications for this project
        const applications = await Application.find({ 
            projectId, 
            status: 'approved' 
        }).populate('userId', 'name email');
        
        if (applications.length === 0) {
            return res.status(400).json({ message: 'No approved applications for this project' });
        }
        
        // Shuffle applications randomly
        const shuffledApplications = applications.sort(() => 0.5 - Math.random());
        
        // Generate group names
        const groupNames = [
            'Data Warriors', 'AI Innovators', 'Web Developers', 'Cloud Masters',
            'Mobile Creators', 'Tech Titans', 'Code Crusaders', 'Digital Dynamos',
            'Byte Brigade', 'Pixel Pioneers', 'Logic Legends', 'Algorithm Avengers'
        ];
        
        const groups = [];
        const membersPerGroup = parseInt(groupSize) || 4;
        
        // Create groups
        for (let i = 0; i < shuffledApplications.length; i += membersPerGroup) {
            const groupApplications = shuffledApplications.slice(i, i + membersPerGroup);
            
            if (groupApplications.length > 0) {
                const groupName = groupNames[groups.length % groupNames.length] + ' ' + (groups.length + 1);
                
                const group = new Group({
                    name: groupName,
                    projectId,
                    members: groupApplications.map((app, index) => ({
                        userId: app.userId._id,
                        role: index === 0 ? 'leader' : 'member'
                    })),
                    createdBy: req.user.userId
                });
                
                await group.save();
                
                // Create notifications for all group members
                for (const member of groupApplications) {
                    const notification = new Notification({
                        userId: member.userId._id,
                        title: 'Group Assignment',
                        message: `You have been assigned to group "${groupName}" for the project`,
                        type: 'group'
                    });
                    await notification.save();
                }
                
                await group.populate('members.userId', 'name email');
                await group.populate('projectId', 'title');
                
                groups.push(group);
            }
        }
        
        res.json({ message: 'Groups generated successfully', groups });
    } catch (error) {
        console.error('Generate groups error:', error);
        res.status(500).json({ message: 'Error generating groups', error: error.message });
    }
});

const { OAuth2Client } = require('google-auth-library');
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Google OAuth login endpoint
app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    
    // Verify the Google token
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    
    const payload = ticket.getPayload();
    const { sub, email, name, picture } = payload;
    
    // Check if user exists in database
    let user = await User.findOne({ email });
    
    if (!user) {
      // Create new user if doesn't exist
      user = new User({
        googleId: sub,
        email,
        name,
        avatar: picture,
        role: 'student' // Default role
      });
      await user.save();
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        avatar: user.avatar
      }
    });
  } catch (error) {
    console.error('Google auth error:', error);
    res.status(400).json({
      success: false,
      message: 'Google authentication failed'
    });
  }
});


// Start server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

