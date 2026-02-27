import express from "express";
import axios from "axios";
import multer from "multer";
import cors from "cors";
import dotenv from "dotenv";
import fs from "fs";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const upload = multer({ dest: "uploads/" });
const API_KEY = process.env.VT_API_KEY;

// ---- SCAN URL ----
app.post("/scan-url", async (req, res) => {
  try {
    const { url } = req.body;
    const response = await axios.post(
      "https://www.virustotal.com/api/v3/urls",
      new URLSearchParams({ url }),
      { headers: { "x-apikey": API_KEY } }
    );
    res.json(response.data);
  } catch (err) { res.status(500).json({ error:"URL scan failed" }); }
});

// ---- SCAN FILE ----
app.post("/scan-file", upload.single("file"), async (req, res) => {
  try {
    const filePath = req.file.path;
    const response = await axios.post(
      "https://www.virustotal.com/api/v3/files",
      fs.createReadStream(filePath),
      { headers: { "x-apikey": API_KEY, "Content-Type":"multipart/form-data" } }
    );
    fs.unlinkSync(filePath);
    res.json(response.data);
  } catch(err){ res.status(500).json({ error:"File scan failed" }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>console.log(`🔥 RX Threat Backend running on port ${PORT}`));
