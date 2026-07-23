import process from "node:process";
import express, { type Request, type Response } from "express";
import { MongoClient, ServerApiVersion, Collection } from "mongodb";
import cors from "cors";
import dotenv from "dotenv";
import nodemailer from "nodemailer";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const port = process.env.PORT;

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const uri = process.env.MONGODB_URI as string;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

interface User {
  email: string;
  name?: string;
  [key: string]: any;
}

const database = client.db("Scamshield");
const userCollection: Collection<User> = database.collection("user");

async function run() {
  try {
    await client.connect();

    app.post(
      "/send-email",
      async (req: Request, res: Response): Promise<any> => {
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
          `,
          };

          await transporter.sendMail(mailOptions);

          return res.status(200).json({ success: true });
        } catch (error: any) {
          console.error("Mail Error:", error);
          return res.status(500).json({
            success: false,
            message: error.message,
          });
        }
      },
    );

    app.get(
      "/user/:email",
      async (req: Request, res: Response): Promise<any> => {
        const { email } = req.params;

        if (!email) {
          return res
            .status(400)
            .json({ success: false, message: "Email is required" });
        }
        const result = await userCollection.findOne({ email });
        return res.json(result);
      },
    );

    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!",
    );
  } finally {
    // Keep connection alive for express server
  }
}

run().catch(console.dir);

app.get("/", (req: Request, res: Response) => {
  res.send("Hello World!");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
