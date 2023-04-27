require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000;

var users = [];

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONDODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
  mongoUrl:
  `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
      secret: mongodb_session_secret
    }
})

app.use(session({
  secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
  }
))

app.get('/', (req,res) => {
  if (!req.session.authenticated) {
    var html = `
      <button><a href="/signup">Sign Up</a></button>
      <button><a href="/login">Log In</a></button>
    `;
    res.send(html);
  } else {
    var html = `
    Hello, ${mongodb_user};
    <button><a href="/members">Go to Members Area</a></button>
    <button><a href="/logout">Logout</a></button>
    `;
    res.send(html);
  }
});

app.get('/signup', (req,res) => {
  var html = `
    <p>create user</p>
    <form action='/submitInfo' method='post'>
      <input name='name' type='text' placeholder='name'>
      <input name='email' type='text' placeholder='email'>
      <input name='password' type='text' placeholder='password'>
      <button>Submit</button>
    </form>
  `;
  res.send(html);
});

app.get('/login', (req,res) => {
  var html = `
    <p>log in</p>
    <form action='/loginSubmit' method='post'>
      <input name='email' type='text' placeholder='email'>
      <input name='password' type='text' placeholder='password'>
      <button>Submit</button>
    </form>
  `;
  res.send(html);
});

app.post('/submitInfo', async (req,res) => {
  var name = req.body.name;
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object(
    {
      name: Joi.string().required(),
      email: Joi.string().required(),
      password: Joi.string().max(20).required()
    });
  
  const validationResult = schema.validate({name, email, password});
  if (validationResult.error != null) {
      console.log(validationResult.error);
      if (!name) {
        var html = `
          <p>Name is required.</p>
          <div><a href="/signup">Try again</a></div>
        `
        res.send(html);
        return;
      } if (!email) {
        var html = `
        <p>Email is required.</p>
        <div><a href="/signup">Try again</a></div>
      `
        res.send(html);
        return;
      } if (!password) {
        var html = `
        <p>Password is required.</p>
        <div><a href="/signup">Try again</a></div>
      `
        res.send(html);
        return;
    }
  }
  
  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({name: name, email: email, password: hashedPassword});
  console.log("Inserted user");

  req.session.authenticated = true;
  req.session.name = name;
  req.session.cookie.maxAge = expireTime;

  res.redirect('/loggedIn');
  return;
})

app.post('/loginSubmit',  async (req,res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().required();
	const validationResult = schema.validate(email) && schema.validate(password);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}
  
  const result = await userCollection.find({email: email}).project({name: 1, email: 1, password: 1, _id: 1}).toArray();

  console.log(result);
	if (result.length != 1) {
		console.log("Invalid email/password combination.");
		res.redirect("/login");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.email = email;
    req.session.name = result[0].name;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/loggedIn');
		return;
	}
	else {
    var html = `
    Invalid email/password combination.
    <div><a href="/login">Try again</a></div>
    `
    res.send(html);
		return;
	}
})

app.get('/loggedIn', (req,res) => {
  if (!req.session.authenticated) {
    res.redirect('/login');
  } else {
    res.redirect('/members');
  }
})

app.get('/members', (req,res) => {
  if (!req.session.authenticated) {
    res.redirect("/");
  } else {
    var html = `
    Hello, ${req.session.name}
    <button><a href="/logout">Sign out</a></button>
    `
    res.send(html);
  }
})

app.get('/logout', (req,res) => {
  req.session.destroy();
  res.redirect('/');
})

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
  res.status(404);
  res.send("Page not found - 404");
})

app.listen(port, () => {
  console.log("Listening on port " + port);
})


