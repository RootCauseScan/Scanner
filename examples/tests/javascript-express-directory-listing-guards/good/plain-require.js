const id = require('url').parse(require('http').request.url, true).query.id || '';
const sql = "SELECT * FROM users WHERE id = '" + id + "'";
require('mysql').query(sql);
