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
const clustersLogger = winston.createLogger({
  level: 'info',
  transports: [
    new winston.transports.File({
      filename: 'clustersErrors.log',
      level: 'error'
    }),
    new winston.transports.File({
      filename: 'clustersRequests.log',
      level: 'info'
    })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  indexLogger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}



/* GET clusters listing. */
router.get('/', function (req, res, next) {
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
      var decipheredCookie = decryptCookie(sessionID);

      clustersLogger.log({
        level: 'info',
        sessionID: sessionID,
        clientIP: req.ip,
        userAgent: req.userAgent,
        message: 'clusterList hit!'
      });

      var accountsCollection = db.db("BubbleChat").collection("Clusters");
      var clusterList = [];

      accountsCollection.find({
        "members": username
      }.toArray(function (err, result) {
        if (err) {

          indexLogger.log({
            level: 'error',
            message: 'Cannot find account in collection! Error: ' + err,
          });

        } else {

          result.forEach(function (entry) {
            clusterList.push(entry);
          });

          res.render('clusterList', {
            title: 'Clusters',
            clusterList: clusterList
          });
        }
      }));

      db.close();
    }
  })
});

router.get('/new', function (req, res, next) {
  res.render('newCluster', {
    title: 'New Cluster'
  });
});

router.post('/addCluster', function (req, res, next) {
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
      var decipheredCookie = decryptCookie(sessionID);

      var newCluster = {
        name: req.body.username,
        description: req.body.description,
        admin: decipheredCookie,
        members: [admin],
      };

      var accountsCollection = db.db("BubbleChat").collection("Accounts");
      accountsCollection.insert([newAccount], function (err, result) {
        if (err) {

          indexLogger.log({
            level: 'error',
            message: 'Cannot add cluster in database! Error: ' + err,
          });

        } else {
          res.redirect('clusterList');
        }
      })
    }
  })
});

module.exports = router;