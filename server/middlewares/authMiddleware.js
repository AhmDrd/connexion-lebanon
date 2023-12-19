const jwt = require("jsonwebtoken");


module.exports = (req, res, next) => {
  try {
    if (!req.headers.Authorization || !req.headers.Authorization.startsWith('Bearer ')) {
      return res.status(401).send({
        message: "Auth failed. No valid token found in the Authorization header",
        success: false,
      });
    }
    
    const token = req.headers.Authorization.split(" ")[1];
    if (!token) {
      return res.status(401).send({
        message: "Auth failed. No token provided",
        success: false,
      });
    }
    
    const decodedToken = jwt.verify(token, process.env.jwt_secret);
    req.params.userId = decodedToken.userId;
    next();
  } catch (error) {
    res.status(401).send({
      message: "Auth failed. Invalid token",
      success: false,
      error: error.message
    });
  }
};
