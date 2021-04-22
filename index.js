const express = require("express");
require("dotenv").config();
const app = express();
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const Users = require("./Models/User");

mongoose.connect(process.env.MongoDB, {
  useCreateIndex: true,
  useFindAndModify: true,
  useUnifiedTopology: true,
  useNewUrlParser: true,
});

mongoose.connection.on("open", () => {
  console.log("Connected to DB.");
});

app.use(express.json());

const jwt = require("jsonwebtoken");
app.post("/signup", (req, res) => {
  let password = req.body.password;
  bcrypt.genSalt(10, function (err, salt) {
    bcrypt.hash(password, salt, async function (err, hash) {
      let user = new Users({
        name: req.body.name,
        email: req.body.email,
        password: hash,
      });

      await user.save();
      res.send(user);
    });
  });
});

app.post("/login", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;
  //   check if user exist
  let user = await Users.findOne({ email: email });
  // early exist
  if (!user) {
    res.status(400).json("You need to sign up.");
    return;
  }
  bcrypt.compare(password, user.password, (err, result) => {
    if (result) {
      let payload = {
        name: user.name,
        email: user.email,
      };

      let token = jwt.sign(payload, process.env.SECRETKEY, { expiresIn: '1h'});
      res.json(token);
    } else {
      res.status(400).json("Password or email is wrong");
    }
  });
});

app.listen(8000, () => {
  console.log("app is listening");
});
