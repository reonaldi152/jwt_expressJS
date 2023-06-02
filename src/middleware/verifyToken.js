const jwt = require('jsonwebtoken');

function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;
  
    if (!authHeader) {
      return res.status(401).json({ error: 'Token tidak ditemukan' });
    }
  
    const token = authHeader.split(' ')[1];
  
    jwt.verify(token, jwtSecret, (error, decoded) => {
      if (error) {
        return res.status(401).json({ error: 'Token tidak valid' });
      }
  
      // Token valid, menyimpan data yang terdekripsi di objek req untuk penggunaan selanjutnya
      req.user = decoded;
  
      // Melanjutkan eksekusi ke endpoint berikutnya
      next();
    });
  }

module.exports = verifyToken;