require("dotenv").config();
const express = require("express");
const app = express();
//const port = process.env.TOKEN_SERVER_PORT;
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const users = [];
app.use(express.json());

// accessTokens
let accessTokens = [];
function generateAccessToken(user) {
  const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15m",
  });
  accessTokens.push(accessToken);
  return accessToken;
}
// refreshTokens
let refreshTokens = [];
function generateRefreshToken(user) {
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "20m",
  });
  refreshTokens.push(refreshToken);
  return refreshToken;
}

app.get("/createUser", async (req, res) => {
  res.send(process.env.ACCESS_TOKEN_SECRET);
});

app.post("/createUser", async (req, res) => {
  const user = req.body.name;
  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  users.push({ user: user, password: hashedPassword });
  res.send(users);
  console.log(users);
});

//AUTHENTICATE LOGIN AND RETURN JWT TOKEN

app.post("/login", async (req, res) => {
  const user = users.find((c) => c.user == req.body.name);
  //check to see if the user exists in the list of registered users
  if (user == null) res.status(404).send("User does not exist!");
  //if user does not exist, send a 400 response
  if (await bcrypt.compare(req.body.password, user.password)) {
    const accessToken = generateAccessToken({ user: req.body.name });
    const refreshToken = generateRefreshToken({ user: req.body.name });
    res.json({ accessToken: accessToken, refreshToken: refreshToken });
  } else {
    res.status(401).send("Password Incorrect!");
  }
});

//REFRESH TOKEN API
app.post("/refreshToken", (req, res) => {
  if (!refreshTokens.includes(req.body.token))
    res.status(400).send("Refresh Token Invalid");
  refreshTokens = refreshTokens.filter((c) => c != req.body.token);
  //remove the old refreshToken from the refreshTokens list
  const accessToken = generateAccessToken({ user: req.body.name });
  const refreshToken = generateRefreshToken({ user: req.body.name });
  //generate new accessToken and refreshTokens
  res.json({ accessToken: accessToken, refreshToken: refreshToken });
});

app.delete("/logout", (req, res) => {
  refreshTokens = refreshTokens.filter((c) => c != req.body.token);
  //remove the old refreshToken from the refreshTokens list
  res.status(204).send("Logged out!");
});

function validateToken(req, res, next) {
  //get token from request header
  const authHeader = req.headers["authorization"];
  const token = authHeader.split(" ")[1];
  //the request header contains the token "Bearer <token>", split the string and use the second value in the split array.
  if (token == null) res.sendStatus(400).send("Token not present");
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      res.status(403).send("Token invalid");
    } else {
      req.user = user;
      next(); //proceed to the next action in the calling function
    }
  }); //end of jwt.verify()
} //end of function

app.get("/posts", validateToken, (req, res) => {
  console.log("Token is valid");
  console.log(req.user.user);
  res.send(`${req.user.user} successfully accessed post`);
});

app.listen(process.env.PORT);
