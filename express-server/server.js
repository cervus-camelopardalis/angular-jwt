const express = require('express');
const app = express();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv').config();

/* Middleware */
app.use(cors());
app.use(express.json()); /* Parse requests of content-type - application/json */
app.use(express.urlencoded({ extended: true })); /* Parse requests of content-type - application/x-www-form-urlencoded */

/* Routes */
/***************************************************/
/****************** Get all users ******************/
/***************************************************/
/* Thunder Client: GET http://localhost:5000/users */
/* JSON: { "email": "bob@email.com", "password": "password123" } */
/* JSON: { "email": "alice@email.com", "password": "password123" } */
const users = [];
app.get('/users', verifyToken, (req, res) => {
  /* If verifyToken doesn't return any error, it means that the token is valid and the user is set (req.user = user) */
  /* Goal: only return "user" that the user has access to */
  /* If Bob signs in --> show him his data (i.e., his e-mail and password) */
  /* If Alice signs in --> show her her data (i.e., her e-mail and password) */
  res.json(users.filter(user => user.email === req.user.email));
});

/***************************************************/
/********************* Sign up *********************/
/***************************************************/
/* Thunder Client: POST http://localhost:5000/users */
/* JSON: { "email": "bob@email.com", "password": "password123" } */
/* JSON: { "email": "alice@email.com", "password": "password123" } */
app.post('/users', async(req, res) => {
  try {
    /* Generate salt --> if two users have identical password, hashes will be different */
    /* Goal: Impossible to crack other identical password if one is cracked */
    const salt = await bcrypt.genSalt();
    /* Use salt and hash the password */
    const hashedPassword = await bcrypt.hash(req.body.password, salt);
    const user = { email: req.body.email, password: hashedPassword };
    users.push(user);
    res.status(201).send();
  } catch {
    res.status(500).send();
  }
});

/***************************************************/
/********************* Sign in *********************/
/***************************************************/
/* Thunder Client: POST http://localhost:5000/users/signin */
/* JSON: { "email": "bob@email.com", "password": "password123" } */
/* JSON: { "email": "alice@email.com", "password": "password123" } */
app.post('/users/signin', async(req, res) => {

  /* (1) USER AUTHENTICATION: verify who a user is */

  /* Compare an e-mail that was passed in vs. e-mails from the list of users */
  const user = users.find(user => req.body.email === user.email);
  /* If an e-mail does NOT exist in the list of users... */
  if (user == null) {
    /* ...return an error */
    return res.status(400).send('Incorrect e-mail.');
  }
  /* If an e-mail does exist in the list of users... */
  try {
    /* ...and if the password that was passed in is the same as password of that particular user from the list of users... */
    if (await bcrypt.compare(req.body.password, user.password)) {

      /* (2) USER AUTHORIZATION: verify what they have access to */

      /* ...generate a JWT */
      const email = req.body.email;
      const user = { email: email };
      const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
      res.json({ accessToken: accessToken });
    } else { /* ...but the password that was passed in is NOT the same as password of that particular user from the list of users... */
      /* ...return an error */
      return res.status(400).send('Incorrect password.');
    }
  } catch {
    res.status(500).send();
  }
});

function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  /* If we have an authHeader return the authHeader token portion (using split), otherwise return undefined */
  const token = authHeader && authHeader.split(' ')[1]; /* There's a space between BEARER and token like this: BEARER l345gteo43056450654n35ph350956u0... */

  /* If the user doesn't send the token... */
  if (token == null) {
    /* ...return an error */
    return res.sendStatus(401)
  }

  /* Verify the token (token and secret needed) */
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    /* If the token sent by the user is not valid... */
    if (err) {
      /* ...return an error */
      return res.sendStatus(403);
    }

    /* If the token sent by the user is valid... */
    /* ...set the user on request */
    req.user = user;
    next(); /* Move on from middleware */
  });
}

/* Set port and listen for requests */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}.`);
});