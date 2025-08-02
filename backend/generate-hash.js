const bcrypt = require('bcrypt');

const password = 'admin12345';

bcrypt.hash(password, 10, (err, hashedPassword) => {
  if (err) {
    console.error("Error hashing password", err);
    return;
  }
  console.log("Hashed Password:", hashedPassword);
});
