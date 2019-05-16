module.exports = function(app, passport, provisioning, strategyConfig) {

  const log = require('winston')
    , moment = require('moment')
    , ActiveDirectoryStrategy = require('passport-activedirectory')\
    , User = require('../models/user')
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

  passport.use(new ActiveDirectoryStrategy({
      integrated: false,
      ldap: {
        url: strategyConfig.url,
        baseDN: strategyConfig.baseDN,
        username: strategyConfig.username,
        password: strategyConfig.password
      }
    },
    function(profile, ad, done) {
      // TODO determine what profile info I get back
      console.log('Successful active directory login profile is', profile);
      User.getUserByAuthenticationId('activedirectory', profile.username, function(err, user) {
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
                type: 'activedirectory',
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
          return done(null, user, {access_token: accessToken});
        }
      });
    });
  ));

  // DEPRECATED retain old routes as deprecated until next major version.
  app.post(
    '/api/login',
    function authenticate(req, res, next) {
      log.warn('DEPRECATED - The /api/login route will be removed in the next major version, please use /auth/local/signin');

      passport.authenticate('local', function(err, user, info = {}) {
        if (err) return next(err);

        if (!user) {
          return res.status(401).send(info.message);
        }

        req.user = user;
        next();
      })(req, res, next);
    },
    provisioning.provision.check(provisioning.strategy),
    parseLoginMetadata,
    function(req, res) {
      new api.User().login(req.user,  req.provisionedDevice, req.loginOptions, function(err, token) {
        res.json({
          token: token.token,
          expirationDate: token.expirationDate,
          user: userTransformer.transform(req.user, {path: req.getRoot()}),
          api: config.api
        });
      });
    }
  );

  app.post(
    '/auth/local/signin',
    function authenticate(req, res, next) {
      passport.authenticate('local', function(err, user, info = {}) {
        if (err) return next(err);

        if (!user) {
          return res.status(401).send(info.message);
        }

        req.login(user, function(err) {
          if (err) return next(err);

          res.json({
            user: userTransformer.transform(req.user, {path: req.getRoot()})
          });
        });
      })(req, res, next);
    }
  );

  // DEPRECATED retain old routes as deprecated until next major version.
  app.post('/api/devices',
    function authenticate(req, res, next) {
      passport.authenticate('local', function(err, user) {
        if (err) return next(err);

        if (!user) {
          return next('route');
        }

        req.login(user, function(err) {
          next(err);
        });
      })(req, res, next);
    },
    function(req, res, next) {
      log.warn('DEPRECATED - The /api/devices route will be removed in the next major version, please use /auth/local/devices');

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

  // Create a new device
  // Any authenticated user can create a new device, the registered field will be set to false.
  app.post('/auth/local/devices',
    isAuthenticated,
    function(req, res, next) {
      const newDevice = {
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
    '/auth/local/authorize',
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
