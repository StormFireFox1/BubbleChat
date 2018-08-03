var createError = require('http-errors');
var express = require('express');
var path = require('path');
var hbs = require('hbs');
var cookieParser = require('cookie-parser');
var config = require('./config/config')
var client = require('mongodb').MongoClient;
var logger = require('morgan');
var fs = require('fs');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
var clusterRouter = require('./routes/clusters');
var bubbleRouter = require('./routes/bubbles');

var app = express();
var server = require('http').Server(app);
var io = require('socket.io')(server);

// view engine setup
app.set('views', path.join(__dirname, 'views'));
hbs.registerPartials(__dirname + "/views/partials")
app.set('view engine', 'hbs');

app.use(logger('combined', {
  stream: fs.createWriteStream('logs/HTTPRequests.log', {
    flags: 'a'
  })
}));
app.use(express.json());
app.use(express.urlencoded({
  extended: false
}));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', indexRouter);
app.use('/users', usersRouter);
app.use('/clusters', clusterRouter);
app.use('/bubbles', bubbleRouter);

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

io.sockets.on('connection', function (socket) {
  socket.on('sendhandle', function (handle) {
    socket.handle = handle;
  });

  socket.on('attachtobubble', function (bubbleName) {
    socket.join(bubbleName);
  });

  socket.on('sendmessage', function (data) {
    client.connect(config.mongodb.uri, function (err, db) {
      if (err) {
        throw err;
      }

      var bubblesCollection = db.db('BubbleChat').collection('Bubbles');
      bubblesCollection.updateOne({
        "name": data.room
      }, {
        $push: {
          messageHistory: {
            handle: data.handle,
            message: data.message
          }
        }
      }, function (err, result) {
        if (err) {
          throw err;
        } else {
          db.close();
        }
      });
    });
    socket.emit('updatechat', data);
    socket.in(data.room).emit('updatechat', data);
  });

});

module.exports = {
  app: app,
  server: server
};