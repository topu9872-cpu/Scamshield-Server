import process from "node:process";
import express, { type Request, type Response } from "express";
import { Collection, MongoClient, ServerApiVersion } from "mongodb";
import cors from "cors";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import { scanSchema } from "./scan.js";
import { checkUrlWithGoogle } from "./googleSafeBrowsing.js";
import { analyzeWithGemini } from "./gemini.js";
import { checkUrlWithVirusTotal } from "./utils/virusTotal.js";
const app = express();
dotenv.config();
app.use(cors());
app.use(express.json());

const port = Number(process.env.PORT ?? 5000);

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const uri = process.env.MONGODB_URI;
if (!uri) {
  throw new Error("MONGODB_URI environment variable is required");
}

const dbName = process.env.MONGODB_DB_NAME ?? "ScamShield";

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
  connectTimeoutMS: 10000,
  serverSelectionTimeoutMS: 10000,
});

interface User {
  email: string;
  name?: string;
  [key: string]: any;
}
interface ScanHistory {
  userEmail: string;
  type: "url" | "email" | "phone" | "text";
  value: string;
  score: number;
  isScam: boolean;
  summary: string;
  insights: string[];
  createdAt: Date;
}

async function run() {
  try {
    await client.connect();

    const db = client.db(dbName);
    const userCollection = db.collection<User>("users");
    const scanHistoryCollection = db.collection<ScanHistory>("scan_history");
    // const scanHistoryCollection: Collection<ScanHistory>;
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
        const result = scanSchema.safeParse(req.body);
        if (!result.success) {
          return res
            .status(400)
            .json({ success: false, errors: result.error.flatten() });
        }

        const { type, value } = result.data;
        const { userEmail } = req.body;

        if (!userEmail) {
          return res.status(400).json({
            success: false,
            message: "User email is required",
          });
        }

        const googleResult = await checkUrlWithGoogle(value);

        // Optional: Keep VirusTotal call as requested in your snippet
        await checkUrlWithVirusTotal(value).catch((err) =>
          console.error("VirusTotal Error:", err),
        );

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

        try {
          aiResult = await analyzeWithGemini(type, value, googleResult);
        } catch (error) {
          console.error("Gemini Error:", error);
          aiResult.insights.push(
            "Gemini quota exceeded. Using fallback analysis.",
          );
        }

        await scanHistoryCollection.insertOne({
          userEmail,
          type,
          value,
          score: aiResult.score,
          isScam: aiResult.isScam,
          summary: aiResult.summary,
          insights: aiResult.insights,
          createdAt: new Date(),
        });

        return res.json(aiResult);
      } catch (error) {
        console.error("Scanner Route Error:", error);
        return res.status(500).json({
          success: false,
          message:
            error instanceof Error ? error.message : "Internal Server Error",
        });
      }
    });

    app.get(
      "/scan-history/:email",
      async (req: Request, res: Response): Promise<any> => {
        try {
          const { email } = req.params;

          if (!email) {
            return res.status(400).json({
              success: false,
              message: "Email is required",
            });
          }

          const history = await scanHistoryCollection
            .find({ userEmail: email })
            .sort({ createdAt: -1 })
            .toArray();

          return res.status(200).json({
            success: true,
            history,
          });
        } catch (error) {
          console.error("Scan History Error:", error);

          return res.status(500).json({
            success: false,
            message:
              error instanceof Error ? error.message : "Internal Server Error",
          });
        }
      },
    );

    const server = app.listen(port, () => {
      console.log(`ScamShield server running on port ${port}`);
    });

    server.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "EADDRINUSE") {
        const fallbackPort = port + 1;
        console.warn(
          `Port ${port} is already in use. Trying fallback port ${fallbackPort}...`,
        );
        app.listen(fallbackPort, () => {
          console.log(`ScamShield server running on port ${fallbackPort}`);
        });
      } else {
        console.error("Server error:", err);
        process.exit(1);
      }
    });
  } catch (error) {
    console.error("MongoDB connection error:", error);
  }
}

run();
