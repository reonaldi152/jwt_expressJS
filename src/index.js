// Import library dan konfigurasi dari file .env
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { Sequelize, DataTypes } = require('sequelize');
const {verifyToken} = require('./middleware/verifyToken');

const app = express();
const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET;

// Koneksi ke database MySQL
const sequelize = new Sequelize(
  process.env.DB_DATABASE,
  process.env.DB_USERNAME,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: 'mysql'
  }
);

// Model Pengguna
const User = sequelize.define('User', {
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false
  }
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors());

// Sinkronisasi model dengan database
sequelize.sync()
  .then(() => {
    console.log('Tabel pengguna telah dibuat');
  })
  .catch(error => {
    console.error('Terjadi kesalahan saat sinkronisasi tabel:', error);
  });

// Endpoint untuk registrasi
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Periksa apakah pengguna sudah terdaftar
    const existingUser = await User.findOne({
      where: { username }
    });

    if (existingUser) {
      return res.status(400).json({ error: 'Username sudah terdaftar' });
    }

    // Enkripsi password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Tambahkan pengguna ke database
    await User.create({
      username,
      password: hashedPassword
    });

    res.status(201).json({ message: 'Registrasi berhasil' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Terjadi kesalahan pada server' });
  }
});

// Endpoint untuk login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Cari pengguna berdasarkan username
    const user = await User.findOne({
      where: { username }
    });

    // Periksa apakah pengguna ditemukan dan cocokkan password
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Username atau password salah' });
    }

    // Buat token JWT
    const token = jwt.sign({ username }, jwtSecret, { expiresIn: '1h' });

    // Set token sebagai cookie pada response
    res.cookie('token', token, { httpOnly: true });

    res.json({
        code: 200,
        message: 'Login berhasil',
        access_token: token
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Terjadi kesalahan pada server' });
  }
});

// Endpoint untuk logout
app.post('/logout', (req, res) => {
  // Dapatkan token dari header Authorization
  const token = req.headers.authorization;
  console.log(`ini token ${token}`);

  if (!token) {
    return res.status(401).json({ error: 'Token tidak ditemukan' });
  }

  // Hapus cookie yang berisi token
  res.clearCookie('token');

  // Lakukan validasi dan verifikasi token
  jwt.verify(token, jwtSecret, (error, decoded) => {
    if (error) {
      return res.status(401).json({ error: 'Token tidak valid' });
    }

    // Lakukan tindakan tambahan setelah berhasil logout, misalnya menghapus token dari database atau melakukan log aktivitas

    res.json({ message: 'Logout berhasil' });
  });
});

// Endpoint untuk mendapatkan daftar pengguna
app.get('/users', async (req, res) => {
  try {
    // Dapatkan token dari header Authorization
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({ error: 'Token tidak ditemukan' });
    }

    // Split header Authorization untuk mendapatkan token
    const token = authHeader.split(' ')[1];

    // Verifikasi token
    jwt.verify(token, jwtSecret, async (error, decoded) => {
      if (error) {
        return res.status(401).json({ error: 'Token tidak valid' });
      }

      // Lakukan tindakan yang diperlukan untuk mendapatkan daftar pengguna dari database
      try {
        // Lakukan tindakan yang diperlukan untuk mendapatkan daftar pengguna dari database
        const users = await User.findAll({
          attributes: { exclude: ['password'] } // Exclude field 'password' from the result
        });

        // Mengembalikan daftar pengguna tanpa password
        res.json(users);
      } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Terjadi kesalahan pada server' });
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Terjadi kesalahan pada server' });
  }
});



// Jalankan server
app.listen(port, () => {
  console.log(`Server berjalan pada http://localhost:${port}`);
});
