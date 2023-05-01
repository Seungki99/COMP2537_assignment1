require("./utils.js");

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 24 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include("databaseConnection");

const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store
    saveUninitialized: false,
    resave: true,
  })
);

app.get("/", (req, res) => {
  if (req.session.authenticated) {
    // User is logged in
    res.send(`
          <p>Hello, ${req.session.name}!</p>
          <button onclick="window.location.href='/members'">Members Area</button><br>
          <button onclick="window.location.href='/logout'">Log Out</button>
        `);
  } else {
    // User is not logged inc
    res.send(`
          <button onclick="window.location.href='/signup'">Sign Up</button><br>
          <button onclick="window.location.href='/login'">Log In</button>
        `);
  }
});

app.get("/nosql-injection", async (req, res) => {
  var username = req.query.user;

  if (!username) {
    res.send(
      `<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`
    );
    return;
  }
  console.log("user: " + username);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);

  //If we didn't use Joi to validate and check for a valid URL parameter below
  // we could run our userCollection.find and it would be possible to attack.
  // A URL parameter of user[$ne]=name would get executed as a MongoDB command
  // and may result in revealing information about all users or a successful
  // login without knowing the correct password.
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(
      "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
    );
    return;
  }

  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);

  res.send(`<h1>Hello ${username}</h1>`);
});

//sing up function
app.get("/signup", (req, res) => {
  var html = `
        sign up
        <form action='/submitUser' method='post'>
        <input name='name' type='text' placeholder='name'><br>
        <input name='email' type='text' placeholder='email'><br>
        <input name='password' type='password' placeholder='password'><br>
        <button>Submit</button>
        </form>
        `;
  res.send(html);
});

app.post("/submitUser", async (req, res) => {
  var name = req.body.name;
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ name, email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(
      'All information is required. <br><br> <a href="/signup">Try again</a>'
    );
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    name: name,
    email: email,
    password: hashedPassword,
  });
  console.log("Inserted user");

  req.session.authenticated = true;
  req.session.user = { name: name, email: email };
  req.session.cookie.maxAge = expireTime;

  res.redirect("/members");
});

app.get("/login", (req, res) => {
  var html = `
    Log in
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='email'><br>
    <input name='password' type='password' placeholder='password'><br>
    <button>Submit</button>
    </form>
    `;
  res.send(html);
});

app.post("/loggingin", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    var errorMessage = validationResult.error.details[0].message;
    res.send(`${errorMessage}. <a href="/login">Try again</a>.`);
    return;
  }

  const user = await userCollection.findOne({ email: email });

  if (!user) {
    res.send("User not found <br><br><a href='/login'>Try again</a>.");
    return;
  }

  const match = await bcrypt.compare(password, user.password);

  if (!match) {
    res.send("Wrong password <br><br> <a href='/login'>Try again</a>.");
    return;
  }

  req.session.authenticated = true;
  req.session.name = user.name;

  res.redirect("/members");
});

app.get("/loggedin", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/login");
  }
  var html = `
    You are logged in!
    `;
  res.redirect("/members");
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  var html = `
    You are logged out.
    `;
  res.send(html);
});


  
app.get("/cat/:id", (req, res) => {
  var cat = req.params.id;

  if (cat == 1) {
    res.send("<img src='/cat1.jpg' style='width:250px;'>");
  } else if (cat == 2) {
    res.send("Socks: <img src='/cat2.jpg' style='width:250px;'>");
  }  else if (cat == 3) {
    res.send("Socks: <img src='/cat3.jpg' style='width:250px;'>");
  }
});

app.get('/members', (req, res) => {
    // Check if the user has a valid session
    if (req.session.authenticated) {
      // User is logged in
      const name = req.session.name;
  
      // Select a random image from the available images
      const images = ["cat1.jpg", "cat2.jpg", "cat3.jpg"];
      const randomIndex = Math.floor(Math.random() * images.length);
      const randomImage = images[randomIndex];
  
      // Render the members page with the user's name and a random image
      res.send(`
        <h1>Hello, ${name}!</h1>
        <img src="/${randomImage}" alt="Random Image" style="max-width: 500px; height: auto;">
        <br><br>
        <a href="/logout">Log Out</a>
      `);
    } else {
      // User is not logged in, redirect to the home page
      res.redirect('/');
    }
  });
  

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  res.send("Page not found - 404");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
