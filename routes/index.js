var express = require('express');
var router = express.Router();

/* GET home page. This returns the homepage */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'BubbleChat' });
});

module.exports = router;
