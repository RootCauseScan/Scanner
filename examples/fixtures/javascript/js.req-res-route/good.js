import express from 'express';
const app = express();
app.get('/u', (req, res) => {
  res.send(sanitize(req.query.id));
});
