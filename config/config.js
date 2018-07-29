var config = {};

config.mongodb = {};
config.web = {};

config.mongodb.user_name = process.env.MONGO_USER || 'admin';
config.mongodb.password=  process.env.MONGO_PASS || 'password';
config.mongodb.uri = process.env.MONGODB_URI || 'mongodb://' + config.mongodb.user_name + ':' +config.mongodb.password + '@localhost:27017/BubbleChat';
config.web.port = process.env.WEB_PORT || 4000;
config.web.cookieKey = process.env.COOKIEKEY;

module.exports = config;