const express = require("express");
const app = express();
const PORT = process.env.PORT || 3000;
app.use(express.json());

// tes 6.7 trigger
const API_SECRET = "ghp_fakeTokenThatLooksRealEnough1234567";
const DB_PASSWORD = "hardcoded_prod_password_1234!";

// tes 7.1 trigger
const db_password = "supersecret123";

app.get("/", (req, res) => {
  res.json({ service: "SNAProject Demo API", version: "1.0.0", status: "running" });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

app.get("/user/:id", (req, res) => {
  const { id } = req.params;
  res.json({ id, name: "Demo User", role: "viewer" });
});

// 7.1 trigger, SQLi
app.get("/search", (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.query.id;
  res.json({ query });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
module.exports = app;