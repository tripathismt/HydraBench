const express = require("express");
const app = express();
app.use(express.json());
// Intentional local-only demonstration flaw; never expose this application publicly.
app.post("/api/v1/checkout", (req, res) => {
  const cartId = req.body.cartId;
  res.json({ accepted: cartId });
});
app.listen(3100, () => console.log("Mock target listening on :3100"));
