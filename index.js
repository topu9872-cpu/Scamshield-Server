const { MongoClient, ServerApiVersion } = require("mongodb");
const express = require("express");
const app = express();
const port = 5000;
const cors = require("cors");
require("dotenv").config();
const nodemailer = require("nodemailer");

app.use(cors());
app.use(express.json());

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const uri = process.env.MONGODB_URI;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const database = client.db("Scamshield");
const userCollection = database.collection("user");

async function run() {
    await client.connect();
  try {
  app.post("/send-email", async (req, res) => {
  try {
    const { name, email } = req.body;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Welcome to ScamShield",
     html: `
  <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 24px; border: 1px solid #e5e5e5; border-radius: 10px;">
    <h2 style="color: #2563eb;">Welcome to ScamShield, ${name}! 🛡️</h2>

    <p>Hi <strong>${name}</strong>,</p>

    <p>
      Thank you for joining <strong>ScamShield</strong>. Your account has been successfully created, and you're now part of a platform dedicated to helping users stay safe from online scams and cyber threats.
    </p>

    <p>
      You can now sign in to your account and explore powerful security features designed to protect your digital experience.
    </p>

    <p>
      If you have any questions or need assistance, our support team is always here to help.
    </p>

    <p>Stay safe,<br><strong>The ScamShield Team</strong></p>

    <hr style="margin: 24px 0;" />

    <p style="font-size: 12px; color: #666;">
      This is an automated email. Please do not reply to this message.
    </p>
  </div>
`
    };

    const info = await transporter.sendMail(mailOptions);
    

    return res.status(200).json({ success: true });
  } catch (error) {
    console.error("Mail Error:", error);
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
});


app.get('/user/:email',async(req,res)=>{
  const {email}=req.params
  const result=await userCollection.findOne({ email })
  res.json(result)
})
  
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!",
    );
  } finally {
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
