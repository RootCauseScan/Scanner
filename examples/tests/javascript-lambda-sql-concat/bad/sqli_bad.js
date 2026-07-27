// Vulnerable: Lambda handler builds SQL from event
exports.handler = function(event, context) {
  const id = event.queryStringParameters?.id || '';
  const sql = "SELECT * FROM users WHERE id = '" + id + "'";
  return db.query(sql);
};
