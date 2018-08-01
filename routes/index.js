/* Config stage, define all of the necessary libraries */
var express = require('express');
var config = require('../config/config')
var client = require('mongodb').MongoClient
var winston = require('winston');
var router = express.Router();
var bcrypt = require('bcrypt');

/* Setup all the variables for the database */
var dbURL = config.mongodb.uri;
var crypto = require('crypto'),
  algorithm = 'aes-192-gcm',
  password = config.web.cookieKey;

function encryptCookie(cookie) {
  var cipher = crypto.createCipher(algorithm, password)
  var crypted = cipher.update(cookie, 'utf-8', 'hex')
  crypted += cipher.final('hex');
  return crypted;
}

function decryptCookie(cookie) {
  var decipher = crypto.createDecipher(algorithm, password)
  var dec = decipher.update(cookie, 'hex', 'utf-8')
  return dec;
}

// Declare logging
const indexLogger = winston.createLogger({
  level: 'info',
  transports: [
    new winston.transports.File({
      filename: 'logs/indexErrors.log',
      level: 'error'
    }),
    new winston.transports.File({
      filename: 'logs/indexRequests.log',
      level: 'info'
    })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  indexLogger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}



/* GET home page. This returns the homepage */
router.get('/', function (req, res, next) {
  res.render('index', {
    title: 'BubbleChat',
    cookie: req.cookies.sessionID
  });
});

router.get('/login', function (req, res, next) {
  if (req.cookies.sessionID) {
    res.redirect('/account', 303);
  }

  res.render('login', {
    title: "Login",
    cookie: req.cookies.sessionID
  });
});

router.get('/findtags', function (req, res, next) {
  if (!req.cookies.sessionID) {
    res.redirect('/login', 303);
  }

  res.render('findtags', {
    title: "Find Tags",
    cookie: req.cookies.sessionID
  })
});

router.get('/signup', function (req, res, next) {
  if (req.cookies.sessionID) {
    res.redirect('/account', 303);
  }

  res.render('signup', {
    title: 'Sign Up'
  });
});

router.post('/authChallenge', function (req, res, next) {
  client.connect(dbURL, function (err, db) {
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

      accountsCollection.findOne({
        "username": username
      }, function (err, result) {
        if (err) {

          indexLogger.log({
            level: 'error',
            message: 'Cannot find account in collection! Error: ' + err,
          });

        } else if (result && bcrypt.compareSync(password, result.password)) {
          var encryptedCookie = encryptCookie(username);

          res.cookie('sessionID', encryptedCookie, {
            maxAge: Date.now() + 24 * 60 * 60 * 1000
          }); // 24 hours expiration time
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
  client.connect(dbURL, function (err, db) {
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
          res.redirect('/findtags');
        }
      });

      db.close();

    }
  })
});

router.get('/account', function (req, res, next) {
  client.connect(dbURL, function (err, db) {
    if (err) {

      indexLogger.log({
        level: 'error',
        message: 'Cannot connect to database! Error: ' + err,
      });

    } else {

      if (!req.cookies.sessionID) {
        res.redirect('login', 303);
      }

      var sessionID = req.cookies.sessionID;
      var decipheredCookie = decryptCookie(sessionID)

      indexLogger.log({
        level: 'info',
        sessionID: sessionID,
        clientIP: req.ip,
        userAgent: req.userAgent,
        message: 'accountPage hit!'
      });

      var accountsCollection = db.db("BubbleChat").collection("Accounts");

      accountsCollection.findOne({
        "username": decipheredCookie
      }, function (err, result) {
        if (err) {

          indexLogger.log({
            level: 'error',
            message: 'Cannot find account in collection! Error: ' + err,
          });

        } else if (result) {
          var studentAccount = result;
          res.render('account', {
            title: 'My Account',
            username: result.username,
            firstname: result.firstname,
            lastname: result.lastname,
            dateofbirth: result.dateofbirth,
            tags: result.tags,
            cookie: req.cookies.sessionID
          });
        } else {
          res.redirect('login');
        }
      });

      db.close();

    }
  })
});

router.post("/updateTags", function (req, res, next) {
  client.connect(dbURL, function (err, db) {
    if (err) {

      indexLogger.log({
        level: 'error',
        message: 'Cannot connect to database! Error: ' + err,
      });

    } else {

      if (!req.cookies.sessionID) {
        res.redirect('login', 303);
      }

      var sessionID = req.cookies.sessionID;
      var decipheredCookie = decryptCookie(sessionID)
      
      var tagsString = req.body.tagArray;
      var tags = tagsString.split('--');
      tags.pop();

      indexLogger.log({
        level: 'info',
        sessionID: sessionID,
        clientIP: req.ip,
        userAgent: req.userAgent,
        message: 'updateTags hit!'
      });

      var accountsCollection = db.db("BubbleChat").collection("Accounts");

      accountsCollection.updateOne({
        "username": decipheredCookie
      }, {
        $set: {
          "tags": tags
        }
      }, function (err, result) {
        if (err) {

          indexLogger.log({
            level: 'error',
            message: 'Cannot find account in collection! Error: ' + err,
          });

        } else {
          res.send('Successful!');
        }
      });

      db.close();

    }
  })
});

router.get('/authLogOut', function (req, res, next) {
  res.clearCookie('sessionID');

  res.redirect('/');
});

module.exports = router;