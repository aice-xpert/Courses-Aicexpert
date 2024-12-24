
// middlewares/favicon.js
const path = require('path');
const favicon = require('serve-favicon');

const faviconMiddleware = favicon(path.join(__dirname, '../public/images', 'logo.jpg'));

module.exports = faviconMiddleware;

