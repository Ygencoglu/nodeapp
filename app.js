// app.js
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const flash = require('connect-flash');
const { Pool } = require('pg');
const redis = require('redis');
const connectRedis = require('connect-redis'); 
const app = express();  
const amqp = require('amqplib');

let rabbitMQChannel;
amqp.connect('amqp://localhost').then(function(connection) {
    console.log('Connected to RabbitMQ successfully');
    return connection.createChannel();
}).then(function(channel) {
    console.log('RabbitMQ channel created successfully');
    rabbitMQChannel = channel;
}).catch(function(error) {
    console.error('RabbitMQ connection/channel error:', error);
});

// Redis Client oluşturma (redis'in yeni sürümü için)
const redisClient = redis.createClient({
    url: 'redis://localhost:6379', // Redis URL'si
    // password: 'your_redis_password', // Eğer Redis şifre korumalıysa
});
redisClient.connect().catch(console.error);

redisClient.on('error', function(err) {
  console.log('Could not establish a connection with Redis. ' + err);
});

redisClient.on('connect', function(err) {
  console.log('Connected to Redis successfully');
});
// RedisStore'u doğru bir şekilde oluştur
const RedisStore = require('connect-redis');

// Express session ayarları Redis ile
app.use(session({
  secret: 'your_secret_key',
  saveUninitialized: false,
  resave: false,
  cookie: {
      secure: false, // HTTPS kullanıyorsanız true yapın
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 // Örneğin 1 gün için
  }
}));

redisClient.set("testKey", "testValue", redis.print);
redisClient.get("testKey", (err, reply) => {
    if (err) throw err;
    console.log(reply); // "testValue" döndürmesi beklenir
});

// MongoDB bağlantısı
mongoose.connect('mongodb://localhost:27017/kullaniciDB');
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));

// PostgreSQL bağlantısı
const pool = new Pool({
  user: 'yusuf',
  host: 'localhost',
  database: 'kullaniciDetayDB',
  password: '123',
  port: 5432,
});
// RabbitMQ kullanarak mesaj gönderme fonksiyonu
function sendToQueue(queue, message) {
  rabbitMQChannel.assertQueue(queue, {
      durable: false
  });
  rabbitMQChannel.sendToBuffer(queue, Buffer.from(message));
}


// Model tanımlamaları
const User = mongoose.model('User', new mongoose.Schema({
  username: String,
  password: String,
}));

// Express ayarları
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// Passport konfigürasyonu
passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: 'Incorrect username.' });
      }

      const passwordMatch = await bcrypt.compare(password, user.password);
      if (passwordMatch) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Incorrect password.' });
      }
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id)
    .then(user => done(null, user))
    .catch(err => done(err));
});
app.post('/add-details', isLoggedIn, async (req, res) => {
    const { username, city, birthdate } = req.body;

    try {
        // Kullanıcının ID'sini kullanıcı adına göre bul
        const user = await User.findOne({ username: username });
        if (!user) {
            return res.render('add-details', { error: 'User not found.' });
        }

        const userId = user._id;

        // RabbitMQ üzerinden detay ekleme mesajını gönder
        const message = JSON.stringify({ userId, city, birthdate });
        sendToQueue('userDetailsQueue', message);

        res.redirect('/dashboard');
    } catch (err) {
        console.error(err);
        res.render('add-details', { error: 'An error occurred while adding user details.' });
    }
});
// Routes
app.get('/', (req, res) => {
  res.render('index', { message: req.flash('error') });
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/dashboard',
  failureRedirect: '/',
  failureFlash: true,
}));

app.get('/register', (req, res) => {
  res.render('register', { message: req.flash('error') });
});

app.post('/register', async (req, res) => {
  const { username, password, confirmPassword } = req.body;

  // Şifre doğrulaması kontrolü
  if (password !== confirmPassword) {
    req.flash('error', 'Passwords do not match');
    return res.redirect('/register');
  }

  try {
    // Hash the password
    const hash = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = new User({ username, password: hash });

    // Save the user to the database
    await newUser.save();

    res.redirect('/');
  } catch (err) {
    console.error(err);
    req.flash('error', 'User already exists or an error occurred during registration');
    res.redirect('/register');
  }
});

app.get('/dashboard', isLoggedIn, async (req, res) => {
  try {
    // PostgreSQL'den kullanıcının mevcut detayını kontrol et
    const userId = req.user._id;
    const existingDetail = await pool.query('SELECT * FROM user_details WHERE user_id = $1', [userId]);

    // Mevcut detay varsa, detayları göster
    if (existingDetail.rows.length > 0) {
      res.render('dashboard', { user: req.user, existingDetail: existingDetail.rows[0] });
    } else {
      res.render('dashboard', { user: req.user });
    }
  } catch (err) {
    console.error(err);
    res.render('dashboard', { user: req.user, error: 'An error occurred while fetching user details.' });
  }
});

app.get('/add-details', isLoggedIn, async (req, res) => {
  try {
    // PostgreSQL'den kullanıcının mevcut detayını kontrol et
    const userId = req.user._id;
    const existingDetail = await pool.query('SELECT * FROM user_details WHERE user_id = $1', [userId]);

    // Mevcut detay varsa, detayları göster
    if (existingDetail.rows.length > 0) {
      res.render('add-details', { existingDetail: existingDetail.rows[0] });
    } else {
      res.render('add-details');
    }
  } catch (err) {
    console.error(err);
    res.render('add-details', { error: 'An error occurred while fetching user details.' });
  }
});

app.post('/add-details', isLoggedIn, async (req, res) => {
  const { username, city, birthdate } = req.body;

  try {
    // Kullanıcının ID'sini kullanıcı adına göre bul
    const user = await User.findOne({ username: username });
    if (!user) {
      return res.render('add-details', { error: 'User not found.' });
    }

    const userId = user._id;

    // PostgreSQL'den kullanıcının mevcut detayını kontrol et
    const existingDetail = await pool.query('SELECT * FROM user_details WHERE user_id = $1', [userId]);

    if (existingDetail.rows.length > 0) {
      // Mevcut detay varsa, detayları güncelle
      await pool.query('UPDATE user_details SET city = $1, birthdate = $2 WHERE user_id = $3', [city, birthdate, userId]);
    } else {
      // Mevcut detay yoksa, detayları ekle
      await pool.query('INSERT INTO user_details (user_id, city, birthdate) VALUES ($1, $2, $3)', [userId, city, birthdate]);
    }

    res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    res.render('add-details', { error: 'An error occurred while adding user details.' });
  }
});

// Live search route
app.get('/live-search', isLoggedIn, async (req, res) => {
  const query = req.query.query;

  try {
    // MongoDB'den kullanıcıları bul ve sadece gerekli verileri döndür
    const users = await User.find({ username: { $regex: query, $options: 'i' } }, 'username _id');

    res.json(users);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'An error occurred during live search.' });
  }
});

app.get('/search', isLoggedIn, (req, res) => {
  res.render('search');
});

app.post('/search', isLoggedIn, async (req, res) => {
  const searchedUsername = req.body.searchedUsername;

  try {
    // MongoDB'den kullanıcıyı bul
    const user = await User.findOne({ username: searchedUsername });

    if (!user) {
      res.render('search', { error: 'User not found.' });
    } else {
      // PostgreSQL'den kullanıcının detaylarını çek
      const result = await pool.query('SELECT * FROM user_details WHERE user_id = $1', [user._id]);
      res.render('search', { user: user, details: result.rows });
    }
  } catch (err) {
    console.error(err);
    res.render('search', { error: 'An error occurred while searching for the user.' });
  }
});

// Middleware
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/');
}

// Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
