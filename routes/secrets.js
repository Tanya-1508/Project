const express = require('express');
const jwt = require('jsonwebtoken');
const Secret = require('../models/Secret');
const User = require('../models/User');
const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

router.post('/', authMiddleware, async (req, res) => {
  const secret = new Secret({ content: req.body.content, userId: req.userId });
  await secret.save();
  res.json(secret);
});

router.get('/', authMiddleware, async (req, res) => {
  const secrets = await Secret.find({ userId: req.userId });
  res.json(secrets);
});

router.delete('/:id', authMiddleware, async (req, res) => {
  await Secret.deleteOne({ _id: req.params.id, userId: req.userId });
  res.json({ message: 'Secret deleted' });
});

module.exports = router;
