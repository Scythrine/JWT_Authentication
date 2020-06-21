//Environmet Variables
require("dotenv").config();

//Requring modules
const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const fs = require("fs");
const axios = require("axios");
const cors = require("cors");

//Instance of Express
const app = express();

//Cookie Configuration
const cookieConfig = {
  httpOnly: true,
  maxAge: 90000000,
  overwrite: true,
  secure: false,
};

//Global Middlewares
app.use(bodyParser.json());
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(cors());

//Routing
app.get("/", (req, res) => {
  res.send("Welcome to JWT-Authentication");
});

app.get("/home", (req, res) => {
  accessToken = req.cookies.AccessToken;
  refreshToken = req.cookies.RefreshToken;

  verifyingAllToken(accessToken, refreshToken)
    .then((data) => {
      res.send(
        "Welcome " + data.name + ", " + data.workplace + " is proud to have you"
      );
    })
    .catch((e) => {
      res.clearCookie("AccessToken");
      res.cookie("AccessToken", e.message, cookieConfig);
      res.redirect("/home");
    });
});
app.get("/login", (req, res) => {
  res.send("Post your Credentials");
});

app.post("/login", getCredential, (req, res) => {
  login(req.credential[0].name, req.credential[0].password)
    .then((tokens) => {
      res.cookie("AccessToken", tokens.AccessToken, cookieConfig);
      res.cookie("RefreshToken", tokens.RefreshToken, cookieConfig);
      res.redirect("/home");
    })
    .catch((e) => {
      res.send(e.message);
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

function login(name, pass) {
  return axios
    .post("http://localhost:9000/login", { name: name, password: pass })
    .then((response) => {
      return response.data;
    })
    .catch((e) => {
      throw new Error(e.response.data);
    });
}

async function verifyingAllToken(accessToken, refreshToken) {
  try {
    const data = await verfiyAccessToken(accessToken);
    return data;
  } catch (e) {
    const token = await refreshingToken(refreshToken);
    throw new Error(token);
  }
}

function verfiyAccessToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, process.env.ACCESS_TOKEN, (err, data) => {
      !err ? resolve(data) : reject(err);
    });
  });
}

function refreshingToken(token) {
  return axios
    .post("http://localhost:9000/Refreshing", { token: token })
    .then((response) => {
      return response.data;
    })
    .catch((e) => {
      return e;
    });
}
// Server
const port = process.env.PORT;

app.listen(port, () => {
  console.log("Server is running on port: " + port);
});
