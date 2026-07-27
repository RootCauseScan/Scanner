// Safe: parameterized query
exports.handler = function(event, context) {
  const id = event.queryStringParameters?.id || '';
  return db.query('SELECT * FROM users WHERE id = ?', [id]);
};
