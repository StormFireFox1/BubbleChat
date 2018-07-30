var express = require('express');
var config = require('../config/config')
var client = require('mongodb').MongoClient
var winston = require('winston');
var router = express.Router();
var bcrypt = require('bcrypt');

var dbURL = config.mongodb.uri;
var crypto = require('crypto'),
    algorithm = 'aes-192-gcm',
    password = config.web.cookieKey;

function encryptCookie(cookie){
  var cipher = crypto.createCipher(algorithm, password)
  var crypted = cipher.update(cookie, 'utf-8', 'hex')
  crypted += cipher.final('hex');
  return crypted;
}
 
function decryptCookie(cookie){
  var decipher = crypto.createDecipher(algorithm, password)
  var dec = decipher.update(cookie, 'hex', 'utf-8')
  return dec;
}

// Declare logging
const indexLogger = winston.createLogger({
  level: 'info',
  transports: [
    new winston.transports.File({ filename: 'indexErrors.log', level: 'error' }),
    new winston.transports.File({ filename: 'indexRequests.log', level: 'info' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  indexLogger.add(new winston.transports.Console({
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
router.get('/signup', function(req, res, next){
  res.render('signup',{title:"Signup"});
});
router.get('/signup', function (req, res, next) {
  if(!req.cookies.sessionID)
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

      accountsCollection.findOne({"username": username}, function (err, result) {
        if (err) {

          indexLogger.log({
            level: 'error',
            message: 'Cannot find account in collection! Error: ' + err,
          });

        } else if (result  && bcrypt.compareSync(password, result.password)) {
            var encryptedCookie = encryptCookie(username);
          
            res.cookie('sessionID', encryptedCookie, {maxAge: Date.now() + 24 * 60 * 60 * 1000}); // 24 hours expiration time
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
        password: bcrypt.hashSync(req.body.password, 10),
        dateofbirth: req.body.dateofbirth,
        firstname: req.body.firstname,
        lastname: req.body.lastname,
        tags: []
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

router.get('/account', function(req, res, next) {
  client.connect(dbURL, function(err, db) {
    if (err) {

      indexLogger.log({
        level: 'error',
        message: 'Cannot connect to database! Error: ' + err,
      });

    } else {

      if(!req.cookies.sessionID)
      {
     	  res.redirect('login', 303);
      }
      
      var sessionID = req.cookies.sessionID;
      var decipheredCookie = decryptCookie(sessionID)

      var accountsCollection = db.db("BubbleChat").collection("Accounts");

      accountsCollection.findOne({"username": decipheredCookie}, function (err, result) {
        if (err) {

          indexLogger.log({
            level: 'error',
            message: 'Cannot find account in collection! Error: ' + err,
          });

        } else if (result) {
          var studentAccount = result;
          res.render('account', {
            username: result.username,
            firstname: result.firstname,
            lastname: result.lastname,
            dateofbirth: result.dateofbirth,
            tags: result.tags
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
