const dotenv = require('dotenv');
dotenv.config();
const express = require('express');
const app = new express();

const passport = require('passport');
const passportJWT = require('passport-jwt');
const JWTStrategy = passportJWT.Strategy;
const ExtractJWT = passportJWT.ExtractJwt;
const db = require('./configs/db-config');
const bookshelf = require('bookshelf')(db);
const securePassword = require('bookshelf-secure-password');
const bodyParser = require('body-parser');
bookshelf.plugin(securePassword);
const jwt = require('jsonwebtoken');

const User = bookshelf.Model.extend({
    tableName: 'users',
    hasSecurePassword: true
});

const opts = {
    jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET
};

const strategy = new JWTStrategy(opts, (jwt_payload, next) => {
    console.log('payload received', jwt_payload);
    User.forge({ id: jwt_payload.id }).fetch().then(res => {
        next(null, res);
    })
});

passport.use(strategy);
app.use(passport.initialize());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.get("/", (req, res) => {
    res.send("Hello World");
});

app.post('/signup',(req,res)=>{
    console.log(req);
    console.log(req.body);

    if (!req.body.username || !req.body.password || !req.body.email || !req.body.name) {
        res.status(400).send('Please provide username and password');
    }
    const user = new User({
        email: req.body.email,
        user_name: req.body.username,
        full_name: req.body.name,
        password: req.body.password
    });
    console.log(user);
    user.save().then(() => {
        res.send('User created successfully');
    });
})

app.get('/home', passport.authenticate('jwt', { session: false }), (req, res) => {
    res.send('Welcome to the home page!');
});

app.post('/getToken', (req, res) => {
    if(!req.body.email || !req.body.password){
        res.status(401).send('Please provide username and password');
    }
    User.forge({ email: req.body.email }).fetch().then(user => {
        user.authenticate(req.body.password).then(() => {
            const payload = { id: user.id };
            const token = jwt.sign(payload, process.env.JWT_SECRET);
            res.json({ token });
        }).catch(err => {
            res.status(401).send('Invalid username or password');
        });
    });

});
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});