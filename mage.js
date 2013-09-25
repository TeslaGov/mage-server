var express = require("express")
  , mongoose = require('mongoose')
  , path = require("path")
  , fs = require('fs-extra')
  , config = require('./config.json')
  , provision = require('./provision');

// Create directory for storing SAGE media attachments
var attachmentBase = config.server.attachmentBaseDirectory;
fs.mkdirp(attachmentBase, function(err) {
  if (err) {
    console.error("Could not create directory to store MAGE media attachments. "  + err);
  } else {
    console.log("Using '" + attachmentBase + "' as base directory for feature attachments.");
  }
});

// Configure authentication
var authentication = require('./authentication')(config.server.authentication.strategy);
var provisioning = require('./provision/' + config.server.provision.strategy)(provision);
console.log('Authentication: ' + authentication.loginStrategy);
console.log('Provision: ' + provisioning.strategy);

// Configuration of the MAGE Express server
var app = express();
var mongodbConfig = config.server.mongodb;
app.configure(function () {
  mongoose.connect(mongodbConfig.url, {server: {poolSize: mongodbConfig.poolSize}}, function(err) {
    if (err) {
      console.log('Error connecting to mongo database, please make sure mongodbConfig is running...');
      throw err;
    }
  });
  mongoose.set('debug', true);

  app.set('config', config);

  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(authentication.p***REMOVED***port.initialize());
  app.use(app.router);
  app.use(express.static(path.join(__dirname, "public")));
  app.use(function(err, req, res, next) {
    console.error(err.stack);
    res.send(500, 'Internal server error, please contact MAGE administrator.');
  });
});

// Configure routes
require('./routes')(app, {authentication: authentication, provisioning: provisioning});

// Launches the Node.js Express Server
app.listen(4242);
console.log('MAGE Server: Started listening on port 4242.');