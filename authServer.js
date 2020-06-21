//Environmet Variables
require("dotenv").config();

//Requiring modules
const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const fs = require("fs");

//Instance of Express
const app = express();

//Getting data
let dataJSON = fs.readFileSync("./data/data.json");
let data = JSON.parse(dataJSON);

//Global Middlewares
app.use(bodyParser.json());

//Routing
app.get("/", (req, res) => {
  res.send("Welcome to Auth Server");
});

app.post("/Refreshing", refreshingToken, (req, res) => {
  let NewAccessToken = req.newToken;
  console.log("[+] Refreshing, Access-Token sent");
  res.send(NewAccessToken);
});

app.post("/login", getCredential, (req, res) => {
  let name = req.credential[0].name;
  let password = req.credential[0].password;
  login(name, password)
    .then((tokens) => {
      console.log("[+] Access-Token sent");
      console.log("[+] Refresh-Token sent");
      res.json(tokens);
    })
    .catch((e) => {
      res.status(500).send(e.message);
    });
});

//Function and Middlewares

function refreshingToken(req, res, next) {
  jwt.verify(req.body.token, process.env.REFRESH_TOKEN, (err, data) => {
    if (!err) {
      let newToken = getAccessToken(data.user);
      req.newToken = newToken;
      next();
    } else {
      throw err;
    }
  });
}

function getCredential(req, res, next) {
  let name = req.body.name;
  let pass = req.body.password;
  req.credential = [
    {
      name: name,
      password: pass,
    },
  ];
  next();
}

async function login(name, pass) {
  try {
    const userName = await checkName(name);
    const userData = await checkPassword(userName, pass);
    let tokens = getAllToken(userData);
    return tokens;
  } catch (e) {
    throw new Error(e);
  }
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

function getAllToken(userData) {
  let AccessToken = getAccessToken(userData);
  let RefreshToken = getRefreshToken(userData);

  const tokens = {
    AccessToken: AccessToken,
    RefreshToken: RefreshToken,
  };
  return tokens;
}

function getAccessToken(userData) {
  let data = {
    name: userData[0].name,
    workplace: userData[0].workplace,
  };
  return jwt.sign(data, process.env.ACCESS_TOKEN, {
    expiresIn: "10s",
  });
}

function getRefreshToken(userData) {
  let data = {
    name: userData[0].name,
    workplace: userData[0].workplace,
  };
  return jwt.sign(data, process.env.REFRESH_TOKEN, {
    expiresIn: "2w",
  });
}
//Server
const port = process.env.AUTH_PORT;

app.listen(port, () => {
  console.log("Server is running on port: " + port);
});
