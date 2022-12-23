//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const md5 = require("md5")
// const bcrypt = require('bcrypt');
// const saltRounds = 10;

const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const LinkedInStrategy = require("passport-linkedin-oauth2").Strategy;

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

// Setting the Session
app.use(
  session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
  })
);

//Initialising Passport
app.use(passport.initialize());

//telling our app to Use passport to set up session
app.use(passport.session());
app.use(passport.authenticate('session'));//**** */

mongoose.set("strictQuery", true);
mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
  email: String,
  password: String, 
  googleId:String,
  linkedinId:String, 
  secret:String
});

// Passport-local-mongoose - to use this package we have to add this to our Schema !
userSchema.plugin(passportLocalMongoose);
// This is what we're going to use to hash and salt our passwords and to save in our MongoDB Database

// For findOrCreate we have to plugin it also according to the documentation !
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

//Only for serializing locally
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

//We can use for all means for serialising and deserialising
passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username, name: user.name });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
        /*(Comes from passport install and require mongoosefindorcreate package)*/
      User.findOrCreate({ googleId: profile.id }, function (err, user) { return cb(
          err,
          user
        );
      });
    }
  )
); 


///////////////////////////////////////// LINKEDIN ////////////////////////////////////////////// 

passport.use(new LinkedInStrategy({
  clientID: process.env.LINKEDIN_ID,
  clientSecret: process.env.LINKEDIN_SECRET,
  callbackURL: "http://localhost:3000/auth/linkedin/secrets",
  scope: ['r_emailaddress', 'r_liteprofile'],
}, function(accessToken, refreshToken, profile, done) {
  // asynchronous verification, for effect...
  process.nextTick(function () {
    // To keep the example simple, the user's LinkedIn profile is returned to
    // represent the logged-in user. In a typical application, you would want
    // to associate the LinkedIn account with a user record in your database,
    // and return that user instead.
    return done(null, profile);
  });
}));

app.get('/auth/linkedin',
  passport.authenticate('linkedin', { state: 'SOME STATE'  }),
  function(req, res){
    // The request will be redirected to LinkedIn for authentication, so this
    // function will not be called.
  });

  app.get('/auth/linkedin/secrets', passport.authenticate('linkedin', {
    successRedirect: '/secrets',
    failureRedirect: '/login'
  }));
/*
Create a strategy which is going to be the local strategy to authenticate users using their username and password and also to
serialize and deserialise our user. Now the serialise and deserialise is only necessary when we're using sessions.
And what it does is when we tell it to serialize our user it basically creates that fortune cookie and
stuffs the message namely our users identifications into the cookie. And then when we deserialise it basically allows
passport to be able to crumble the cookie and discover the message inside which is who this user is.
And all of their identification so that we can authenticate them on our server.
*/

///////            Level 02                   ///////

// const secret  ="Thisisournewsecrete."
// //Now we use this secret to encrypt our database by adding encrypt as a plugin to our schema and pass secrete as a JS Object
// userSchema.plugin(encrypt,{secret:secret,encryptedFields:["password"]}); //--> Put this before creating the MOdel

//// ENV /////
/*
Install npm i dotenv  
Require at the top (1st Line)---> reuire('dotenv').config(); 
create .env file in Secrets folder (Hidden File)
Add Environment variables to this file as --> SECRET=Thisisournewsecret.  ---> Replace const secret in app.js by SECRET 
To access those environmental variables we've to write process.env.SECRET 
Now replace secret  in line number 26 by process.env.SECRET // or "Thisisournewsecret." by process.env.SECRET
Add File To Gitignore 

*/

/////     Level 03 ////////////////////////
/*
Hashing 
Password-->(Hash Function)--> Hash 
It is not possible to decrypt or convert hash back into the password 
In this level also it is possible to match the hash with hash and Hackers can get it too ! 
To check the login password we have to hash the password typed by the user nad convert it into its hash and then check that hash with the one 
converted while registration ! 

--> We need md5 npm package to hash the required message 


///////////// Level 04 ////////////////////// 

Salting 
Password + Random set of characters  --> Hash ---> Increases number of characters and it'll be more secure ! 
We can use another hashing algorithm than md5 that is bcrypt new gpus also can claculate only 17000 bcrypt hashesh per sec. 
which makes harder to generate hash tables 

Salt rounds

We need BCRYPT PACKAGE 

///////////// Level 05 ////////////////////// 

When we add any item in cart on Amazon it creates a cookie in our browser 
In this there is ID stored and it is related to the item we added in the cart 
If we delete that cookie the item in that cart will be deleted ! 
If we go to another website like if we move to Facebook it shows us the data or item we want to buy on amazon 
using the cookie that amazon had added into our browser !    

Sessions --> For how much time from logging in to Log Out we are using the website and this is what we need to keep user loggged in untill the user log outs ! 

///////////////  PASSPORT /////////////////////////////// 

passport 
passport-local
passport-local-mongoose 
express-session 


///////////// Level 06 ////////////////////// 




*/

app.get("/", function (req, res) {
  res.render("home");
});

//Here is the error in defining the get request below ! 

app.get("/auth/google",
  passport.authenticate('google', { scope: ['profile'] }));

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  }
);

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req, res) {
  // if (req.isAuthenticated()) {
  //   res.render("secrets");
  // } else {
  //   res.redirect("/login");
  // } 

  User.find({"secret":{$ne:null}}, function (err,foundUsers) {
    if(err){
      console.log(err);
    }else{
      if(foundUsers){
        res.render("secrets", {usersWithSecrets:foundUsers})
      }
    }
  })

}); 

app.get("/submit", function (req,res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
}); 

app.post("/submit", function (req,res) {
  const submittedsecret = req.body.secret; 

//Passport save the user who is logged in so that we can save that secret to the users account ! 

  User.findById(req.user.id,function (err,foundUser) {
    if (err) {
      console.log(err); 
    } else {
      if (foundUser) {
        foundUser.secret = submittedsecret; 
        foundUser.save(function () {
          res.redirect("/secrets"); 
        });
      }
    }
  });
});





app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) {
      console.log(err);
    } else {
      res.redirect("/");
    }
  }); //From Passport (PLM)
});

//Whenever we restart the server cookie gets deleted !

app.post("/register", function (req, res) {
  //Using passport-local-mongoose package to set up register and login posts !

  //User.register//(Comes from the package PLM, we can avoid creating new user, saving our user and interacting with mongoose directly
  //instead we are using this package to handle all of this )
  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          // Initiating authentication with local (Using Local Strategy ! )
          res.redirect("/secrets");
        });
      }
    }
  );
});
app.post("/login", function (req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });
  //USing login() function of Passport
  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

// app.post("/register", function (req,res) {

//     bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
//         // Store hash in your password DB.
//         const newuser = new User({
//             email:req.body.username,
//             password:hash
//             // password:md5(req.body.password)
//         });
//         newuser.save(function (err) {
//            if(err){console.log(err);
//            }
//            else{
//             res.render("secrets", {Username:req.body.username});
//            }
//         });
//     });
// })

// app.post("/login", function (req,res) {
//     const username= req.body.username
//     const password= req.body.password

//     User.findOne({email:username},function (err,result) {
//         if(!err){
//             if(result){
//                 // if(result.password===password){
//                 // if(result.password===md5(password)){
//                     bcrypt.compare(password, result.password, function(err, result1) {
//                         // result1 == true
//                         if(result1=== true){
//                             res.render("secrets", {Username:username});
//                         }
//                         else{
//                             res.send("Try Again, Incorrect Password !");
//                         }
//                     });

//                 // }
//             }
//         }
//         else{
//             console.log(err);
//         }
//     })
// })

app.listen(3000, function () {
  console.log("Server Running ! ");
});
