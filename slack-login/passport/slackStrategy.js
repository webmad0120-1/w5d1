const SlackStrategy = require("passport-slack").Strategy;
const passport = require("passport");
const User = require("../models/User");

passport.use(
  new SlackStrategy(
    {
      clientID: process.env.SLACK_CLIENT_ID,
      clientSecret: process.env.SLACK_CLIENT_SECRET
    },
    (accessToken, refreshToken, profile, done) => {
      User.findOne({
        slackID: profile.id
      })
        .then(user => {
          if (user) {
            User.findByIdAndUpdate(
              user._id,
              {
                username: profile.user.name,
                accessToken: accessToken
              },
              { new: true }
            ).then(user => {
              return done(null, user);
            });
          } else {
            const newUser = new User({
              username: profile.user.name,
              slackID: profile.id,
              accessToken: accessToken
            });

            newUser.save().then(user => {
              done(null, user);
            });
          }
        })
        .catch(error => {
          done(error);
        });
    }
  )
);
