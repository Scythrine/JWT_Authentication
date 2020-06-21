//Environmet Variables
require("dotenv").config();

//Requring modules
const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const fs = require("fs");
const { userInfo } = require("os");
const { verify } = require("crypto");
const { RSA_NO_PADDING } = require("constants");
const { json } = require("body-parser");
const { isArray } = require("util");
const { send } = require("process");
const cors = require("cors");
const { promises } = require("dns");

//Instance of Express
const app = express();

//Getting data
let dataJSON = fs.readFileSync("data.json");
let data = JSON.parse(dataJSON);

//Cookie Configuration
const cookieConfig = {
  httpOnly: true,
  maxAge: 90000000,
  overwrite: true,
  secure: false,
};

//Middlewares
app.use(bodyParser.json());
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(cors());

//Routing
app.get("/", (req, res) => {
  res.send("Welcome");
});

app.get("/home", (req, res) => {
  accessToken = req.cookies.AccessToken;
  refreshToken = req.cookies.RefreshToken;

  verifyingAllToken(accessToken, refreshToken).then((d) => {
    if (d.user) res.send(data.filter((x) => x.name == d.user));
    else {
      res.clearCookie("AccessToken");
      res.cookie("AccessToken", d, cookieConfig);
      res.redirect("/home");
    }
  });
});
app.get("/login", (req, res) => {
  res.send("Hello");
});

app.post("/login", getCredential, (req, res) => {
  checkAll(req.credential[0].name, req.credential[0].password).then((data) => {
    if (isArray(data)) {
      let AccessToken = createAccessToken(data[0].name);
      let RefreshToken = createRefreshToken(data[0].name);
      res.cookie("AccessToken", AccessToken, cookieConfig);
      res.cookie("RefreshToken", RefreshToken, cookieConfig);
      res.redirect("/home");
    } else {
      res.send(data);
    }
  });
});

app.delete("/home", (req, res) => {
  res.clearCookie("AccessToken");
  res.clearCookie("RefreshToken");
  res.redirect("/login");
});

//Functions and Custom Middlewares

function getCredential(req, res, next) {
  let name = req.body.name;
  let pass = req.body.pass;
  req.credential = [
    {
      name: name,
      password: pass,
    },
  ];
  next();
}

function checkName(name) {
  return new Promise((resolve, reject) => {
    let userData = data.filter(
      (item) => item.name.toUpperCase() == name.toUpperCase()
    );
    userData !== `undefined` && userData !== null && userData.length > 0
      ? resolve(userData[0].name)
      : reject("User not found");
  });
}

function checkPassword(name, pass) {
  return new Promise((resolve, reject) => {
    let userData = data.filter(
      (item) => item.name == name && item.password == pass
    );
    userData !== `undefined` && userData !== null && userData.length > 0
      ? resolve(userData)
      : reject("Wrong Password");
  });
}

async function checkAll(name, pass) {
  try {
    const userName = await checkName(name);
    const userData = await checkPassword(userName, pass);
    return userData;
  } catch (e) {
    return e;
  }
}
function createAccessToken(user) {
  userData = { user: user };
  return jwt.sign(userData, process.env.ACCESS_TOKEN, {
    expiresIn: "10s",
  });
}
function createRefreshToken(user) {
  userData = { user: user };
  return jwt.sign(userData, process.env.REFRESH_TOKEN, {
    expiresIn: "2w",
  });
}

function verfiyAccessToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, process.env.ACCESS_TOKEN, (err, data) => {
      !err ? resolve(data) : reject(err);
    });
  });
}

function refreshingToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, process.env.REFRESH_TOKEN, (err, data) => {
      if (!err) {
        let newToken = createAccessToken(data.user);
        resolve(newToken);
      } else {
        reject(err);
      }
    });
  });
}

async function verifyingAllToken(accessToken, refreshToken) {
  try {
    const data = await verfiyAccessToken(accessToken);
    return data;
  } catch (e) {
    const token = await refreshingToken(refreshToken);
    return token;
  }
}

// Server
const port = process.env.PORT;

app.listen(port, () => {
  console.log("Server is running on port: " + port);
});
