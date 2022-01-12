const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const db = require('./db-config')

function intialize(passport) {
    const authenticateUser =  (email, password, done) => {
        db('users').where('email', email).first().then( function (user) {
            if (user == null) {
                return done(null, false, { message: 'No user with that email' });
            }
            if (!bcrypt.compareSync(password, user.password)) {
                return done(null, false, { message: 'Password incorrect' });
            }
            return done(null, user);
        })
        .catch(function (err) {
            return done(err);
        });
    };

  passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser));
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser((id, done) => {
    db('users').where({id}).first()
    .then((user) => { done(null, user); })
    .catch((err) => { done(err, null); });
  });

}

module.exports = intialize;
