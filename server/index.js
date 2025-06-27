const express = require("express");
const { exec } = require("child_process");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

app.post("/api/scan", (req, res) => {
  const { target } = req.body;
  console.log("Scanning:", target);

  exec(`python3 scanner/scan.py ${target}`, (err, stdout, stderr) => {
    if (err) {
      console.error("Error:", stderr);
      return res.status(500).json({ error: "Scan failed" });
    }

    try {
      const result = JSON.parse(stdout);
      res.json(result);
    } catch (e) {
      console.error("Parse error:", stdout);
      res.status(500).json({ error: "Failed to parse scan output" });
    }
  });
});

app.listen(4000, () => {
  console.log("Server running on http://localhost:4000");
});
