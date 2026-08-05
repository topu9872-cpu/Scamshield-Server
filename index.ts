import process from "node:process";
import express, { type Request, type Response } from "express";
import { MongoClient, ServerApiVersion, Collection } from "mongodb";
import cors from "cors";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import { scanSchema } from "./scan.js";
import { checkUrlWithGoogle } from "./googleSafeBrowsing.js";
import { analyzeWithGemini } from "./gemini.js";
const app = express();
dotenv.config();
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

app.use(express.json());

async function run() {
  try {
    await client.connect();

    const db = client.db("ScamShield");
    const userCollection = db.collection("users");

    console.log("MongoDB connected successfully");

    app.post("/user", async (req: Request, res: Response): Promise<any> => {
      try {
        const { name, email, password } = req.body;

        if (!email) {
          return res.status(400).json({
            success: false,
            message: " email is required",
          });
        }

        // Check existing user
        const existingUser = await userCollection.findOne({ email });

        if (existingUser) {
          return res.status(409).json({
            success: false,
            message: "User already exists",
          });
        }

        const newUser = {
          name,
          email,
          password,
          createdAt: new Date(),
        };

        const result = await userCollection.insertOne(newUser);

        return res.status(200).json({
          success: true,
          message: "User created successfully",
          user: {
            id: result.insertedId,
            name,
            email,
          },
        });
      } catch (error: any) {
        console.error("Create User Error:", error);

        return res.status(500).json({
          success: false,
          message: error.message,
        });
      }
    });

    // Send Welcome Email

    app.post(
      "/send-email",
      async (req: Request, res: Response): Promise<any> => {
        try {
          const { name, email } = req.body.data;

          if (!email) {
            return res.status(400).json({
              success: false,
              message: " email are required",
            });
          }

          const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Welcome to ScamShield",
            html: `
              <div style="
                font-family: Arial, sans-serif;
                max-width: 600px;
                margin: auto;
                padding: 24px;
                border: 1px solid #e5e5e5;
                border-radius: 10px;
              ">
                <h2 style="color: #2563eb;">
                  Welcome to ScamShield, ${name}! 🛡️
                </h2>

                <p>
                  Hi <strong>${name}</strong>,
                </p>

                <p>
                  Thank you for joining <strong>ScamShield</strong>.
                  Your account has been successfully created, and you're now
                  part of a platform dedicated to helping users stay safe
                  from online scams and cyber threats.
                </p>

                <p>
                  You can now sign in to your account and explore powerful
                  security features designed to protect your digital experience.
                </p>

                <p>
                  If you have any questions or need assistance,
                  our support team is always here to help.
                </p>

                <p>
                  Stay safe,<br />
                  <strong>The ScamShield Team</strong>
                </p>

                <hr style="margin: 24px 0;" />

                <p style="font-size: 12px; color: #666;">
                  This is an automated email.
                  Please do not reply to this message.
                </p>
              </div>
            `,
          };

          await transporter.sendMail(mailOptions);

          return res.status(200).json({
            success: true,
            message: "Welcome email sent successfully",
          });
        } catch (error: any) {
          console.error("Mail Error:", error);

          return res.status(500).json({
            success: false,
            message: error.message,
          });
        }
      },
    );
    // =========================
    // Get User By Email
    // =========================
    app.get(
      "/user/:email",
      async (req: Request, res: Response): Promise<any> => {
        try {
          const { email } = req.params;
          if (!email) {
            return res.status(400).json({
              success: false,
              message: "Email is required",
            });
          }

          const result = await userCollection.findOne({
            email: email,
          });

          return res.status(200).json({
            success: true,
            user: result,
          });
        } catch (error: any) {
          console.error("Get User Error:", error);

          return res.status(500).json({
            success: false,
            message: error.message,
          });
        }
      },
    );

 app.post("/scanner-data", async (req, res) => {
  try {
    // 1. Validate request
    const result = scanSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        success: false,
        errors: result.error.flatten(),
      });
    }

    const { type, value } = result.data;

    // 2. Google Safe Browsing
    const googleResult = await checkUrlWithGoogle(value);

    // 3. Default AI result (fallback)
    let aiResult = {
      isScam: false,
      score: googleResult?.matches?.length ? 95 : 5,
      summary: googleResult?.matches?.length
        ? "Detected by Google Safe Browsing."
        : "No known threats detected.",
      insights: [
        "Google Safe Browsing completed.",
        "AI analysis unavailable.",
      ],
    };

    // 4. Try Gemini
    try {
      aiResult = await analyzeWithGemini(
        type,
        value,
        googleResult
      );
    } catch (error) {
      console.error("Gemini Error:", error);

      aiResult.insights.push(
        "Gemini quota exceeded. Using fallback analysis."
      );
    }

    // 5. Send response
    return res.json(aiResult);

  } catch (error) {
    console.error("Scanner Route Error:", error);

    return res.status(500).json({
      success: false,
      message:
        error instanceof Error
          ? error.message
          : "Internal Server Error",
    });
  }
});


    app.listen(port, () => {
      console.log(`ScamShield server running on port ${port}`);
    });
  } catch (error) {
    console.error("MongoDB connection error:", error);
  }
}

run();
