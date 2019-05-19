module.exports = function(app, passport, provisioning, strategyConfig) {

  const log = require('winston')
    , LdapStrategy = require('passport-ldapauth')
    , User = require('../models/user')
    , Role = require('../models/role')
    , Device = require('../models/device')
    , api = require('../api')
    , config = require('../config.js')
    , userTransformer = require('../transformers/user');

  function parseLoginMetadata(req, res, next) {
    req.loginOptions = {
      userAgent: req.headers['user-agent'],
      appVersion: req.param('appVersion')
    };

    next();
  }

  function isAuthenticated(req, res, next) {
    if (!req.user) {
      return res.sendStatus(401);
    }

    next();
  }

  function authorizeDevice(req, res, next) {
    provisioning.provision.check(provisioning.strategy, {uid: req.param('uid')}, function(err, device) {
      if (err) return next(err);

      if (provisioning.strategy === 'uid' && (!device || !device.registered)) {
        return res.sendStatus(403);
      } else {
        req.device = device;
        next();
      }
    })(req, res, next);
  }

  passport.use(new LdapStrategy({
    server: {
      url: strategyConfig.url,
      bindDN: strategyConfig.bindDN,
      bindCredentials: strategyConfig.bindCredentials,
      searchBase: strategyConfig.searchBase
    }
  },
  function(profile, ad, done) {
    // TODO determine what profile info I get back
    console.log('Successful active directory login profile is', profile);
    User.getUserByAuthenticationId('ldap', profile.username, function(err, user) {
      if (err) return done(err);

      var email = profile.email;

      if (!user) {
        // Create an account for the user
        Role.getRole('USER_ROLE', function(err, role) {
          if (err) return done(err);

          var user = {
            username: profile.username,
            displayName: profile.name,
            email: profile.email,
            active: false,
            roleId: role._id,
            authentication: {
              type: 'ldap',
              id: profile.username
            }
          };

          User.createUser(user, function(err, newUser) {
            return done(err, newUser);
          });
        });
      } else if (!user.active) {
        return done(null, user, { message: "User is not approved, please contact your MAGE administrator to approve your account."} );
      } else {
        return done(null, user);
      }
    });
  }));

  app.post('/auth/ldap/signin', passport.authenticate('ldapauth'));

  function authorizeUser(req, res, next) {
    let token = req.param('access_token');

    if (req.user) {
      next();
    } else if (token) {
      log.warn('DEPRECATED - authorization with access_token has been deprecated, please use a session');
      next(new Error("Not supported"));
    }
  }

  // Create a new device
  // Any authenticated user can create a new device, the registered field
  // will be set to false.
  app.post('/auth/ldap/devices',
    authorizeUser,
    function(req, res, next) {
      var newDevice = {
        uid: req.param('uid'),
        name: req.param('name'),
        registered: false,
        description: req.param('description'),
        userAgent: req.headers['user-agent'],
        appVersion: req.param('appVersion'),
        userId: req.user.id
      };

      Device.getDeviceByUid(newDevice.uid)
        .then(device => {
          if (device) {
            // already exists, do not register
            return res.json(device);
          }

          Device.createDevice(newDevice)
            .then(device => res.json(device))
            .catch(err => next(err));
        })
        .catch(err => next(err));
    }
  );

  app.post(
    '/auth/ldap/authorize',
    isAuthenticated,
    authorizeDevice,
    parseLoginMetadata,
    function(req, res, next) {
      new api.User().login(req.user,  req.provisionedDevice, req.loginOptions, function(err, token) {
        if (err) return next(err);

        res.json({
          token: token.token,
          expirationDate: token.expirationDate,
          user: userTransformer.transform(req.user, {path: req.getRoot()}),
          device: req.device,
          api: config.api
        });
      });

      req.session = null;
    }
  );
};
