require("dotenv").config();
const bodyParser = require("body-parser");
const express = require("express");
const favicon = require("serve-favicon");
const mongoose = require("mongoose");
const path = require("path");
const session = require("express-session");
const MongoStore = require("connect-mongo")(session);
const flash = require("connect-flash");

mongoose.Promise = Promise;
mongoose
  .connect("mongodb://localhost/social-login", {
    useMongoClient: true
  })
  .then(() => {
    console.log(`Connected to Mongo!`);
  })
  .catch(err => {
    console.error("Error connecting to mongo", err);
  });

const app = express();

// Middleware Setup
app.use(
  bodyParser.urlencoded({
    extended: false
  })
);

app.use(
  session({
    secret: "basic-auth-secret",
    cookie: { maxAge: 60000 },
    store: new MongoStore({
      mongooseConnection: mongoose.connection,
      ttl: 24 * 60 * 60 // 1 day
    }),
    resave: true,
    saveUninitialized: true
  })
);
app.use(flash());

require("./passport")(app);

// Express View engine setup
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "hbs");
app.use(express.static(path.join(__dirname, "public")));
app.use(favicon(path.join(__dirname, "public", "images", "favicon.ico")));

app.use((req, res, next) => {
  // default value for title local
  res.locals.title = "Social login with Slack";
  res.locals.user = req.user;
  res.locals.message = req.flash("error");
  next();
});

const indexRouter = require("./routes/indexRouter");
const authRouter = require("./routes/authRouter");

app.use("/auth", authRouter);
app.use("/", indexRouter);

module.exports = app;
