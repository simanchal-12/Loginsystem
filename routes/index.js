var express = require('express');
var router = express.Router();
var mysql = require('mysql');
var con = require('../database/conn');
var bcrypt = require('bcrypt')

/* GET home page. */
router.get('/', function(req, res, next) {
    if (req.session.flag == 1) {
        req.session.destroy();
        res.render('index', { title: 'LoginSystem', message: "Username Already Exists", flag: 1 });

    } else if (req.session.flag == 2) {
        req.session.destroy();
        res.render('index', { title: 'LoginSystem', message: "Registration Done , Please Login", flag: 0 });

    } else if (req.session.flag == 3) {
        req.session.destroy();
        res.render('index', { title: 'LoginSystem', message: "Confirm Password Doesn't Match.", flag: 1 });

    } else if (req.session.flag == 4) {
        req.session.destroy();
        res.render('index', { title: 'LoginSystem', message: "Incorrect Username or Password", flag: 1 });

    } else {
        res.render('index', { title: 'LoginSystem' });

    }
});

//Handle POST request from user registration
router.post('/auth_register', function(req, res, next) {
    var name = req.body.name;
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;
    var cpassword = req.body.cpassword;

    if (cpassword == password) {
        var sql = 'SELECT * FROM users where username=?;';

        con.query(sql, [username], function(err, result, fields) {
            if (err) throw err;

            if (result.length > 0) {
                req.session.flag = 1;
                res.redirect('/')
            } else {
                var hashpassword = bcrypt.hashSync(password, 10);
                var sql = 'INSERT INTO users(name,username,email,password) values(?,?,?,?);';

                con.query(sql, [name, username, email, hashpassword], function(err, result, fields) {
                    if (err) throw err;
                    req.session.flag = 2;
                    res.redirect('/');
                });
            }
        });
    } else {
        req.session.flag = 3;
        res.redirect('/');
    }


});

//Handle POST request for user  LOgin
router.post('/auth_login', function(req, res, next) {

    var username = req.body.username;
    var password = req.body.password;

    var sql = 'select * from users where username=?;';
    con.query(sql, [username], function(err, result, fields) {
        if (err) throw err;

        if (result.length && bcrypt.compareSync(password, result[0].password)) {
            req.session.username = username;
            res.redirect('/home');
        } else {
            req.session.flag = 4;
            res.redirect('/')
        }
    });
});

//Router for homme page
router.get('/home', function(req, res, next) {
    res.render('home', { message: 'welcome, ' + req.session.username })
});

router.get('/logout', function(req, res, next) {
    if (req.session.username) {
        req.session.destroy();
    }
    res.redirect('/');
});


module.exports = router;