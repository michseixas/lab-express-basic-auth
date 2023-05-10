const router = require("express").Router();
const bcrypt = require('bcryptjs'); //encryption
const saltRounds = 14; //number of times you will apply a round of encryption

const isLoggedIn = require("../middleware/isLoggedIn");
const isLoggedOut = require("../middleware/isLoggedOut");
const User = require("../models/User.model")


/* GET home page */
router.get("/", (req, res, next) => {
  res.render("index");
});

//Creating route for Signup - GET
router.get("/signup", isLoggedOut, (req, res, next) => {
  res.render("signup");
});


//Creating route for Signup - POST
router.post("/signup", isLoggedOut, (req, res, next) => {
  
  let { username, password, passwordRepeat } = req.body;

  if(username == "" || password == "" || passwordRepeat == "") {
    let data = {
      errorMessage: "there is information missing!", 
      user: {
        username,
        password,
        passwordRepeat
      }
    }
    res.render("signup", data);
    return;

  } else if(password != passwordRepeat) {
    let data = {
      errorMessage: "passwords should match!", 
      user: {
        username,
        password,
        passwordRepeat
      }
    }
    res.render("signup", data);
    return;

  } 

  User.find({username}) //returns an array
  .then(users => {
    if(users.length != 0) {
      //username exists in the db
      let data = {
        errorMessage: "username already exists", 
        user: {
          username,
          password,
          passwordRepeat
        }
      }
      res.render("signup", data);
      return;
    }

    //we need package bcryptjs
    const salt = bcrypt.genSaltSync(saltRounds);
    const passwordEncrypted = bcrypt.hashSync(password, salt);

    console.log("password encrypted: ", passwordEncrypted);
    User.create({username , password: passwordEncrypted})
    .then(result => {
      res.redirect("/signin");
    })
    .catch(err => next(err))
  })
})


//Creating route for Signin - GET
router.get("/signin", isLoggedOut, (req, res, next) => {
  res.render("signin");
});

//Creating route for Signin - POST - starting signin process
router.post("/signin", isLoggedOut, (req, res, next) => {
  let {username, password} = req.body;

  if (username == "" || password == "" ) {
    res.render("signin", {errorMessage: "information missing"});
    return;
  }

  User.find({username})
  .then(users => {
    if(users.length == 0) { //la busqueda devolvió un array vacio, por lo tanto, usario no existe
      res.render("signin", {errorMessage: "wrong credentials!"});
      return;
    }
    //si no entró en el if es que el usuario existe, por lo tanto hay que comprobar credenciales
  
    let userDB = users[0]; //creamos una variable en la que le asignamos el usuario presente en la base de datos (que será el usuario en la primera posición del array, o sea, [0])
    //compareSync method takes only 2 arguments and returns a boolean value true or false.
    if (bcrypt.compareSync(password, userDB.password)){
      req.session.currentUser = username; //podría ser telefono, email, etc... 
      res.redirect("/profile")
    } else {
      res.render("signin", {errorMessage: "wrong credentials!"});
      return;
    }
  })
});

//Creating route for Profile - GET
router.get("/profile", (req, res, next) => {
  res.render("profile");
});


//Creating route for Profile - GET
router.get("/main", isLoggedIn, (req, res, next) => { //si el usuario esta loggedIn, tiene acceso a main. Si no, es redireccionado a signin 
  res.render("main");
});

//Creating route for Private - GET
router.get("/private", isLoggedIn, (req, res, next) => { //si el usuario esta loggedIn, tiene acceso a private. Si no, es redireccionado a signin
  res.render("private");
});

//Creating the Logout route:
router.get("/logout", isLoggedIn, (req, res, next) => {
  req.session.destroy((err) => {
    if(err) next(err);
    else res.redirect("/signin");
  });

})


module.exports = router;


