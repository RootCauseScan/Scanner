const session = require('cookie-session');
// Insecure: session middleware without secure cookie flag
app.use(session({ keys: ['key'] }));
