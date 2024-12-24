
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    } 
    
    else {
        res.redirect('/login-user');
    }
}

function isAdminAuthenticated(req, res, next) {
    if (req.session.admin) {
        return next();
    } 
    
    else {
        res.redirect('/admin-login-signup');
    }
}

module.exports = {
    isAuthenticated,
    isAdminAuthenticated
};
