const express = require('express');
const path = require('path');
const { MongoClient, ObjectId } = require('mongodb');
const session = require('express-session');
const flash = require('connect-flash');
const bcrypt = require('bcrypt');
const multer = require('multer');
const { sendOtpEmail } = require('./mailer');
require ("dotenv").config();


const app = express();
const PORT = process.env.PORT || 3000;
const uri = process.env.MONGO_URI;
const dbName = 'SecretShelf';

// Middleware setup
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));


app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false
}));

app.use(flash());

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Set storage for uploaded files
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/uploads/'); // Save in public folder
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});


const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB max
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif/;
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.test(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Only images are allowed'));
    }
  }
});



// MongoDB connection
let db;

async function connectToMongo() {
  try {
    const client = await MongoClient.connect(uri, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    db = client.db(dbName);
    console.log("✅ Connected to MongoDB Atlas");
  } catch (err) {
    console.error("❌ MongoDB connection failed:", err);
    process.exit(1); // Stop server if DB fails
  }
}

connectToMongo();

// Middleware to inject flash and user data
app.use((req, res, next) => {
    res.locals.success = req.flash('success');
    res.locals.error = req.flash('error');
    res.locals.user = req.session.user;
    next();
});

app.get('/', isAuthenticated, async (req, res) => {
  const user = req.session.user;

  const secrets = await db.collection('secrets')
    .find({ userId: new ObjectId(user.id) })
    .sort({ createdAt: -1 }) // optional: latest first
    .toArray();

  const secretCount = secrets.length;

  // Calculate weekly secrets
  const now = new Date();
  const oneWeekAgo = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 7);
  const newSecretsThisWeek = secrets.filter(secret =>
    new Date(secret.createdAt) >= oneWeekAgo
  ).length;

  const lastSecretDate = secrets.length
    ? new Date(secrets[0].createdAt).toLocaleDateString()
    : 'N/A';

  res.render('index', {
    user,
    secrets,
    secretCount,
    newSecretsThisWeek,
    lastSecretDate  
  });
});


// Signup
app.get('/signup', (req, res) => {
    res.render('signup');
});

app.post('/signup', async (req, res) => {
  const { fullname, email, phone, password, confirmPassword } = req.body;
  console.log('signup form data:', req.body);

  // Check if passwords match
  if (password !== confirmPassword) {
    req.flash('error', 'Passwords do not match');
    return res.redirect('/signup');
  }

  // Check for existing user by fullname, email, or phone
  const existingUser = await db.collection('users').findOne({
    $or: [
      { fullname },
      { email },
      { phone }
    ]
  });

  if (existingUser) {
    req.flash('error', 'User with this fullname, email, or phone already exists');
    return res.redirect('/signup');
  }

  // Hash password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Save to DB
  await db.collection('users').insertOne({
    fullname,
    email,
    phone, // save phone number
    password: hashedPassword,
    createdAt: new Date()
  });

  req.flash('success', 'Signup successful. Please login.');
  res.redirect('/login');
});


// Login
app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    const { fullname, password } = req.body;

    const user = await db.collection('users').findOne({ fullname });
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
        req.flash('error', 'Invalid fullname or password');
        return res.redirect('/login');
    }

    // Store fullname and email in session
    req.session.user = {
        id: user._id,
        fullname: user.fullname,
        email: user.email || null,
        phone: user.phone || null 
    };

    req.flash('success', 'Login successful');
    res.redirect('/');
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Auth middleware
function isAuthenticated(req, res, next) {
    if (req.session.user) return next();
    req.flash('error', 'Please login to continue');
    res.redirect('/login');
}

// View secrets
app.get('/secrets', isAuthenticated, async (req, res) => {
    const secrets = await db.collection('secrets').find({
        userId: new ObjectId(req.session.user.id)
    }).toArray();
    res.render('secrets', { secrets });
});

// Add secret
app.get('/add_secret', isAuthenticated, (req, res) => {
    res.render('add_secret');
});

app.post('/add_secret', isAuthenticated, async (req, res) => {
  const secret = req.body.secret;

  if (!secret || secret.trim() === '') {
    req.flash('error', 'Secret cannot be empty');
    return res.redirect('/add_secret');
  }

  await db.collection('secrets').insertOne({
    userId: new ObjectId(req.session.user.id),
    text: secret.trim(),
    createdAt: new Date() // <-- this line adds the timestamp
  });

  req.flash('success', 'Secret added successfully');
  res.redirect('/');
});



app.get("/edit_secret/:id", isAuthenticated, async (req, res) => {
  const secret = await db.collection('secrets').findOne({
    _id: new ObjectId(req.params.id),
    userId: new ObjectId(req.session.user.id)
  });

  if (!secret) {
    req.flash('error', 'Secret not found');
    return res.redirect('/secrets');
  }

  res.render("edit_secret", { secret });
});

app.post("/edit_secret/:id", isAuthenticated, async (req, res) => {
  const updatedSecret = req.body.secret;

  await db.collection('secrets').updateOne(
    { _id: new ObjectId(req.params.id), userId: new ObjectId(req.session.user.id) },
    { $set: { text: updatedSecret } }
  );

  res.redirect("/secrets");
});


app.post("/delete_secret/:id", isAuthenticated, async (req, res) => {
  await db.collection('secrets').deleteOne({
    _id: new ObjectId(req.params.id),
    userId: new ObjectId(req.session.user.id)
  });

  res.redirect("/secrets");
});

app.get('/profile', isAuthenticated, async (req, res) => {
    const user = await db.collection('users').findOne({ _id: new ObjectId(req.session.user.id) });

    if (!user) {
        req.flash('error', 'User not found');
        return res.redirect('/login');
    }
    res.render('pages_profile', {user:{
        ...user,
        email:user.email || ''
    }});
});

app.post('/profile', isAuthenticated, upload.single("photo"), async (req, res) => {
  const userId = new ObjectId(req.session.user.id);

  const updatedData = {
    fullname: req.body.fullname,
    email: req.body.email,
    password: req.body.password,
    phone: req.body.phone || null,
    message: req.body.message || null,
    country: req.body.country || null,
  }; 

  // Add image path if uploaded
  if (req.file) {
    updatedData.photo = "/uploads/" + req.file.filename; // This is public path
  }

 await db.collection('users').updateOne({ _id: userId }, { $set: updatedData });

req.session.user.photo = updatedData.photo; // ✅ update session so it's accessible everywhere

const updatedUser = await db.collection('users').findOne({ _id: userId });

 console.log("Saved photo path:", updatedData.photo);

  res.render('pages_profile', { user: updatedUser });
});



app.get('/forgot_password', (req, res) => {
  res.render('forgot_password'); // make this EJS page
});

app.post('/forgot_password', async (req, res) => {
  const { email } = req.body;
  const user = await db.collection('users').findOne({ email });

  if (!user) {
    req.flash('error', 'User not found');
    return res.redirect('/forgot_password');
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
  console.log("OTP generated and sent:");

  const expiry = Date.now() + 10 * 60 * 1000;

  await db.collection('users').updateOne({ _id: user._id }, {
    $set: { otp, otpExpiry: expiry }
  });

  const sent = await sendOtpEmail(email, otp);

  if (sent) {
    req.session.resetEmail = email;
    req.flash('success', 'OTP sent to your email address');
    return res.redirect('/reset_password');
  } else {
    req.flash('error', 'Failed to send OTP via email');
    return res.redirect('/forgot_password');
  }
});


// GET: Show reset password page
app.get('/reset_password', (req, res) => {
  if (!req.session.resetEmail) {
    req.flash('error', 'Please start the password reset process.');
    return res.redirect('/forgot_password');
  }

  res.render('reset_password', { email: req.session.resetEmail });
});


// POST: Handle reset password form
app.post('/reset_password', async (req, res) => {
  const email = req.session.resetEmail;
  const { otp, password, confirmPassword } = req.body;

  if (!email) {
    req.flash('error', 'Session expired. Please restart password reset process.');
    return res.redirect('/forgot_password');
  }

  const user = await db.collection('users').findOne({ email });

  if (!user) {
    req.flash('error', 'User not found.');
    return res.redirect('/forgot_password');
  }

  // Validate OTP
  const currentTime = Date.now();
  if (!user.otp || user.otp !== otp || currentTime > user.otpExpiry) {
    req.flash('error', 'Invalid or expired OTP.');
    return res.redirect('/reset_password');
  }

  // Check password match
  if (!password || password !== confirmPassword) {
    req.flash('error', 'Passwords do not match.');
    return res.redirect('/reset_password');
  }

  // Hash and update password
  const hashedPassword = await bcrypt.hash(password, 10);

  await db.collection('users').updateOne(
    { _id: user._id },
    {
      $set: { password: hashedPassword },
      $unset: { otp: '', otpExpiry: '' }
    }
  );

  // Clear session data
  delete req.session.resetEmail;

  req.flash('success', 'Password has been reset. Please login.');
  res.redirect('/login');
});





// Start server
app.listen(PORT, () => {
    console.log('🚀 website is live at https://project-ihgt.onrender.com');
});
