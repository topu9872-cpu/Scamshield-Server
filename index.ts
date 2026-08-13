import process from "node:process";
import express, { type Request, type Response } from "express";
import { MongoClient, ServerApiVersion } from "mongodb";
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

const dbName = (process.env.MONGODB_DB_NAME ?? "Scamshield").trim();

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
  connectTimeoutMS: 10000,
  serverSelectionTimeoutMS: 10000,
});

let dbConnected = false;
let userCollection: import("mongodb").Collection<User> | null = null;
let scanHistoryCollection: import("mongodb").Collection<ScanHistory> | null =
  null;

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
  // Try to connect to MongoDB but don't block server startup on failure
  try {
    await client.connect();

    const db = client.db(dbName);

    if (!process.env.MONGODB_DB_NAME) {
      console.warn("MONGODB_DB_NAME not set, defaulting to 'Scamshield'");
    }

    userCollection = db.collection<User>("users");
    scanHistoryCollection = db.collection<ScanHistory>("scan_history");

    dbConnected = true;
    console.log("MongoDB connected successfully");
  } catch (error) {
    dbConnected = false;
    console.error("MongoDB connection error:", error);
  }

  app.post("/user", async (req: Request, res: Response): Promise<any> => {
    try {
      const { name, email, password } = req.body;
      if (!email) {
        return res
          .status(400)
          .json({ success: false, message: " email is required" });
      }

      if (!dbConnected || !userCollection) {
        return res
          .status(503)
          .json({ success: false, message: "Database not available" });
      }

      // Check existing user
      const existingUser = await userCollection.findOne({ email });

      if (existingUser) {
        return res
          .status(409)
          .json({ success: false, message: "User already exists" });
      }

      const newUser = { name, email, password, createdAt: new Date() };

      const result = await userCollection.insertOne(newUser);

      return res.status(200).json({
        success: true,
        message: "User created successfully",
        user: { id: result.insertedId, name, email },
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

  app.post("/send-email", async (req: Request, res: Response): Promise<any> => {
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
  });
  // =========================
  // Get User By Email
  // =========================
  app.get("/user/:email", async (req: Request, res: Response): Promise<any> => {
    try {
      const { email } = req.params;
      if (!email) {
        return res.status(400).json({
          success: false,
          message: "Email is required",
        });
      }

      if (!dbConnected || !userCollection) {
        return res
          .status(503)
          .json({ success: false, message: "Database not available" });
      }

      const result = await userCollection.findOne({ email: email });

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
  });

  app.post("/scanner-data", async (req, res) => {
    try {
      const parsed = scanSchema.safeParse(req.body);

      if (!parsed.success) {
        return res.status(400).json({
          success: false,
          errors: parsed.error.flatten(),
        });
      }

      const { type, value } = parsed.data;
      const { userEmail } = req.body;

      if (!userEmail) {
        return res.status(400).json({
          success: false,
          message: "User email is required",
        });
      }

      if (!dbConnected || !scanHistoryCollection) {
        return res.status(503).json({
          success: false,
          message: "MongoDB is not connected. Scan result was not saved.",
        });
      }

      // Run security checks
      const googleResult = await checkUrlWithGoogle(value).catch(() => null);

      const virusTotalResult = await checkUrlWithVirusTotal(value).catch(
        () => ({
          stats: {
            malicious: 0,
            suspicious: 0,
            harmless: 0,
            undetected: 0,
          },
          status: "unavailable",
          analysisId: "",
        }),
      );

      const { malicious, suspicious } = virusTotalResult.stats;
      const googleMatches = Array.isArray((googleResult as any)?.matches)
        ? (googleResult as any).matches.length
        : 0;

      // Evidence-based score
      const evidenceScore = Math.min(
        (malicious ? 70 : 0) + (suspicious ? 20 : 0) + (googleMatches ? 60 : 0),
        100,
      );

      let aiResult = {
        isScam: evidenceScore >= 50,
        score: evidenceScore,
        summary:
          googleMatches && !malicious
            ? "Security detection triggered by Google Safe Browsing."
            : evidenceScore >= 50
              ? "Potential security threat detected."
              : "No major known threat detected.",
        insights: [
          `VirusTotal malicious: ${malicious}`,
          `VirusTotal suspicious: ${suspicious}`,
          googleMatches
            ? "Google Safe Browsing detected a threat."
            : "Google Safe Browsing found no known threat.",
        ],
      };

      // Gemini (optional)
      try {
        const gemini = await analyzeWithGemini(
          type,
          value,
          googleResult,
          virusTotalResult,
        );

        aiResult = {
          isScam: aiResult.isScam || gemini.isScam,
          score: Math.max(evidenceScore, gemini.score),
          summary: aiResult.isScam ? aiResult.summary : gemini.summary,
          insights: gemini.insights.slice(0, 3),
        };
      } catch (error) {
        console.warn("Gemini unavailable, using evidence score.");
      }

      const scanDocument = {
        userEmail,
        type,
        value,
        score: aiResult.score,
        isScam: aiResult.isScam,
        summary: aiResult.summary,
        insights: aiResult.insights,
        createdAt: new Date(),
      };

      const inserted = await scanHistoryCollection.insertOne(scanDocument);

      return res.status(200).json({
        success: true,
        ...aiResult,
        scanId: inserted.insertedId.toString(),
      });
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

        if (!dbConnected || !scanHistoryCollection) {
          return res
            .status(503)
            .json({ success: false, message: "Database not available" });
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
  
      app.listen(port, () => {
        console.log(`ScamShield server running on port ${port}`);
      });
   
  });
}

run();
