const express = require('express');
const http = require('http');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const socketio = require('socket.io');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketio(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

// ===== Environment Variables =====
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost/chat_app';
const PORT = process.env.PORT || 5000;

// ===== MongoDB Connection =====
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// ===== Schemas =====
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  passwordHash: String,
});

const messageSchema = new mongoose.Schema({
  from: String,
  to: String, // null = group message
  content: String,
  type: { type: String, default: 'text' }, // text, image, voice
  timestamp: { type: Date, default: Date.now },
  room: String, // room id for group/private chat
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

// ===== Middleware =====
app.use(cors({
  origin: [
    "https://your-frontend.vercel.app", // ✅ Replace with your Vercel frontend URL
  ],
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true,
}));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ===== Multer setup (file uploads) =====
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const uniqueSuffix =
      Date.now() + '-' + Math.round(Math.random() * 1e9) + path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix);
  }
});
const upload = multer({ storage });

// ===== JWT auth middleware =====
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.sendStatus(401);

  const token = authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// ===== Routes =====

// Root route for testing
app.get("/", (req, res) => {
  res.send("✅ Chat backend is running...");
});

// Register
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: 'Username and password required' });

  const exists = await User.findOne({ username });
  if (exists) return res.status(400).json({ message: 'User exists already' });

  const passwordHash = await bcrypt.hash(password, 10);
  const user = new User({ username, passwordHash });
  await user.save();

  res.json({ message: 'User registered' });
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ message: 'Invalid credentials' });

  const isValid = await bcrypt.compare(password, user.passwordHash);
  if (!isValid) return res.status(400).json({ message: 'Invalid credentials' });

  const token = jwt.sign(
    { id: user._id, username: user.username },
    JWT_SECRET,
    { expiresIn: '1d' }
  );
  res.json({ token, username: user.username });
});

// Get chat history for a room
app.get('/api/messages/:room', authenticateToken, async (req, res) => {
  const { room } = req.params;
  if (!room) return res.status(400).json({ message: 'Room required' });
  const messages = await Message.find({ room }).sort({ timestamp: 1 }).lean();
  res.json(messages);
});

// Upload file endpoint
app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'File upload failed' });
  const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  res.json({ url: fileUrl });
});

// ===== Socket.IO =====
const onlineUsers = new Map(); // username -> socket.id

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Authentication error'));

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return next(new Error('Authentication error'));
    socket.user = user;
    next();
  });
});

io.on('connection', (socket) => {
  onlineUsers.set(socket.user.username, socket.id);
  io.emit('onlineUsers', Array.from(onlineUsers.keys()));

  socket.on('joinRoom', (room) => {
    socket.join(room);
  });

  socket.on('chatMessage', async ({ room, to, content, type }) => {
    const from = socket.user.username;
    const msg = new Message({ from, to, content, type, room });
    await msg.save();

    io.to(room).emit('chatMessage', {
      from,
      to,
      content,
      type,
      timestamp: msg.timestamp,
      room,
    });
  });

  socket.on('typing', ({ room, isTyping }) => {
    socket.to(room).emit('typing', { from: socket.user.username, isTyping });
  });

  socket.on('disconnect', () => {
    onlineUsers.delete(socket.user.username);
    io.emit('onlineUsers', Array.from(onlineUsers.keys()));
  });

  // Video call signaling
  socket.on('video-offer', ({ to, offer }) => {
    const toSocketId = onlineUsers.get(to);
    if (toSocketId) {
      io.to(toSocketId).emit('video-offer', { from: socket.user.username, offer });
    }
  });
  socket.on('video-answer', ({ to, answer }) => {
    const toSocketId = onlineUsers.get(to);
    if (toSocketId) {
      io.to(toSocketId).emit('video-answer', { from: socket.user.username, answer });
    }
  });
  socket.on('new-ice-candidate', ({ to, candidate }) => {
    const toSocketId = onlineUsers.get(to);
    if (toSocketId) {
      io.to(toSocketId).emit('new-ice-candidate', { from: socket.user.username, candidate });
    }
  });
});

// ===== Start Server =====
server.listen(PORT, () => console.log(`🚀 Server listening on port ${PORT}`));