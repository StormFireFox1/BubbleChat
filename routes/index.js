var express = require('express');
var config = require('../config/config')
var client = require('mongodb').MongoClient
var router = express.Router();

var dbURL = config.mongodb.uri;
var cookieEncryptor = require('crypto').createCipher('aes-192-gcm', config.web.cookieKey);

// Declare logging
const indexLogger = require('winston').createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: '../log/indexErrors.log', level: 'error' }),
    new winston.transports.File({ filename: '../log/indexRequests.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

/* GET home page. This returns the homepage */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'BubbleChat' });
});

router.get('/login', function (req, res, next) {
  res.render('login', {title: "Login"});
});

router.get('/signup', function (req, res, next) {
  if(!req.cookies.username)
  {
  	res.redirect('login', 303);
  }

  res.render('signup', { title: 'Sign Up' });
});

router.post('/authChallenge', function (req, res, next) {
  client.connect(dbURL, function(err, db) {
    if (err) {

      indexLogger.log({
        level: 'error',
        message: 'Cannot connect to database! Error: ' + err,
      });

    } else {

      var username = req.body.username;
      var password = req.body.password;

      indexLogger.log({
        level: 'info',
        username: username,
        password: password,
        clientIP: req.ip,
        userAgent: req.userAgent,
        message: 'authChallenge hit!'
      });

      var accountsCollection = db.db("BubbleChat").collection("Accounts");

      accountsCollection.find({"username": username, "password": password}).toArray(function (err, result) {
        if (err) {

          indexLogger.log({
            level: 'error',
            message: 'Cannot find account in collection! Error: ' + err,
          });

        } else if (result.length) {
          var encryptedCookie = cookieEncryptor.update(username, 'utf8', 'hex');
          encryptedCookie += cookieEncryptor.final('hex');
        
          res.cookie(sessionID, encryptedCookie, {maxAge: Date.now() + 24 * 60 * 60 * 1000});
          res.redirect('account')
        } else {
          res.redirect('login');
        }
      });

      db.close();
    }
  })
});

router.post('/authNew', function (req, res, next) {
  client.connect(dbURL, function(err, db) {
    if (err) {

      indexLogger.log({
        level: 'error',
        message: 'Cannot connect to database! Error: ' + err,
      });

    } else {

      var newAccount = {
        username: req.body.username,
        password: req.body.password,
        dateofbirth: req.body.dateofbirth,
        firstname: req.body.firstname,
        lastname: req.body.lastname,
        tags: {}
      };
      
      indexLogger.log({
        level: 'info',
        account: newAccount,
        clientIP: req.ip,
        userAgent: req.userAgent,
        message: 'authNew hit!'
      });

      var accountsCollection = db.db("BubbleChat").collection("Accounts");
      accountsCollection.insert([newAccount], function (err, result) {
        if (err) {

          indexLogger.log({
            level: 'error',
            message: 'Cannot add account in database! Error: ' + err,
          });

        } else {
          res.redirect('login');
        }
      });

      db.close();

    }
  })
});
module.exports = router;
