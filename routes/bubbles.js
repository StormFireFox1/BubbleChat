/* Config stage, define all of the necessary libraries */
var express = require('express');
var config = require('../config/config')
var client = require('mongodb').MongoClient
var winston = require('winston');
var router = express.Router();
var bcrypt = require('bcrypt');
var randomURLGenerator = require('gfycat-style-urls'); 

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

/**
 * Randomize array element order in-place.
 * Using Durstenfeld shuffle algorithm.
 */
function shuffleArray(array) {
    for (var i = array.length - 1; i > 0; i--) {
        var j = Math.floor(Math.random() * (i + 1));
        var temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }
}

// Declare logging
const bubblesLogger = winston.createLogger({
    level: 'info',
    transports: [
        new winston.transports.File({
            filename: 'logs/bubblesErrors.log',
            level: 'error'
        }),
        new winston.transports.File({
            filename: 'logs/bubblesRequests.log',
            level: 'info'
        })
    ]
});

if (process.env.NODE_ENV !== 'production') {
    bubblesLogger.add(new winston.transports.Console({
        format: winston.format.simple()
    }));
}

function randomBubbleName() {
    return randomURLGenerator.generateCombination(2, "", true);
}

router.get('/:bubbleName', function (req, res, next) {
    if (!req.cookies.sessionID) {
        res.redirect('/login', 303);
    } else {
        client.connect(dbURL, function (err, db) {
            if (err) {

                bubblesLogger.log({
                    level: 'error',
                    message: 'Cannot connect to database! Error: ' + err,
                });

            } else {
                var sessionID = req.cookies.sessionID;
                var decipheredCookie = decryptCookie(sessionID)

                bubblesLogger.log({
                    level: 'info',
                    sessionID: sessionID,
                    clientIP: req.ip,
                    userAgent: req.userAgent,
                    bubbleName: req.params.bubbleName,
                    message: 'bubbleChatRoom hit!'
                });

                var bubblesCollection = db.db('BubbleChat').collection('Bubbles');
                bubblesCollection.findOne({
                    "name": req.params.bubbleName,
                    "members.username": decipheredCookie,
                }, function (err, result) {
                    if (err) {
                        bubblesLogger.log({
                            level: 'error',
                            message: 'Cannot read bubble from database! Error: ' + err,
                        });
                    } else if (result) {
                        var bubbleName = result.name;
                        var accountsCollection = db.db('BubbleChat').collection('Accounts');
                        accountsCollection.findOne({
                            "username": decipheredCookie
                        }, function (err, result) {
                            if (err) {
            
                                bubblesLogger.log({
                                    level: 'error',
                                    message: 'Cannot find account in collection! Error: ' + err,
                                });
            
                            } else if (result) {

                                res.render('bubble', {
                                    title: req.params.bubbleName + " - BubbleChat",
                                    cookie: req.cookies.sessionID,
                                    bubbleName: req.params.bubbleName,
                                    handle: result.handle
                                })
                            }});

                            db.close();
                    } else {
                        res.redirect(401, '/');
                        db.close();
                    }
                });
            }
        });
    }
});

router.get('/new', function (req, res, next) {
    if (!req.cookies.sessionID) {
        res.redirect('/login', 303);
    }
    res.render('newBubble', {
        title: 'New Bubble',
        cookie: req.cookies.sessionID
    });
});

router.get('/queue', function (req, res, next) {
    if(!req.cookies.sessionID) {
        res.redirect('/login', 303);
    }
    res.render('loadingscreen', {title: 'Bubble Queue', cookie: req.cookies.sessionID});
});

router.post('/initBubble', function (req, res, next) {
    client.connect(dbURL, function (err, db) {
        if (err) {
            bubblesLogger.log({
                level: 'error',
                message: 'Cannot connect to database! Error: ' + err,
            });
        } else {
            var bubblesCollection = db.db('BubbleChat').collection('Bubbles');
            var username = decryptCookie(req.cookies.sessionID);

            var accountsCollection = db.db("BubbleChat").collection("Accounts");
            var membersList = [];

            accountsCollection.findOne({
                "username": username
            }, function (err, result) {
                if (err) {

                    bubblesLogger.log({
                        level: 'error',
                        message: 'Cannot find account in collection! Error: ' + err,
                    });

                } else if (result) {
                    var query = {
                        "tags": {
                            $in: result.tags
                        }
                    };

                    accountsCollection.find(query, {
                        "username": 1,
                        _id: 0
                    }).toArray(function (err, result) {
                        if (err) {
                            bubblesLogger.log({
                                level: 'error',
                                message: 'Cannot find accounts with tags in collection! Error:' + err,
                            })
                        } else if (result.length) {
                            membersList = result;
                        } else {
                            membersList = [-1];
                        }

                        var newBubble = {
                            name: randomBubbleName(),
                            dateCreated: Date.now(),
                            members: membersList,
                            messageHistory: {}
                        };
            
                        bubblesCollection.insertOne(newBubble, function (err) {
                            if (err) {
                                bubblesLogger.log({
                                    level: 'error',
                                    message: 'Cannot insert bubble into database! Error: ' + err
                                })
                            }
                            
                            bubblesLogger.log({
                                level: 'info',
                                message: 'Created bubble! Name: ' + newBubble.name,
                            });

                            res.redirect('/bubbles/' + newBubble.name);

                            db.close();
                        });
                    });
                }
            });

        }
    });  
});

module.exports = router;