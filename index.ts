import process from "node:process";
import express, { type Request, type Response } from "express";
import {
  MongoClient,
  ObjectId,
  ServerApiVersion,
  type Collection,
} from "mongodb";
import cors from "cors";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import { scanSchema } from "./scan.js";
import { checkUrlWithGoogle } from "./googleSafeBrowsing.js";
import { analyzeWithGemini } from "./gemini.js";
import { checkUrlWithVirusTotal } from "./utils/virusTotal.js";

dotenv.config();
const app = express();
app.use(cors(), express.json());

const port = Number(process.env.PORT ?? 5000);
const uri = process.env.MONGODB_URI;
if (!uri) throw new Error("MONGODB_URI is required");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
  connectTimeoutMS: 10000,
  serverSelectionTimeoutMS: 10000,
});

let userCollection: Collection<any>;
let scanHistoryCollection: Collection<any>;

// Helper for error responses
const handleError = (
  res: Response,
  error: unknown,
  message = "Internal Server Error",
) => {
  console.error(message, error);
  return res
    .status(500)
    .json({
      success: false,
      message: error instanceof Error ? error.message : message,
    });
};

async function run() {
  try {
    await client.connect();
    const db = client.db(process.env.MONGODB_DB_NAME?.trim() || "Scamshield");
    userCollection = db.collection("users");
    scanHistoryCollection = db.collection("scan_history");
    console.log("MongoDB connected successfully");
  } catch (error) {
    console.error("MongoDB connection error:", error);
  }

  // --- USERS ---
  app.post("/user", async (req: Request, res: Response): Promise<any> => {
    try {
      const { name, email, password } = req.body;
      if (!email)
        return res
          .status(400)
          .json({ success: false, message: "Email is required" });
      if (!userCollection)
        return res
          .status(503)
          .json({ success: false, message: "Database not available" });

      if (await userCollection.findOne({ email })) {
        return res
          .status(409)
          .json({ success: false, message: "User already exists" });
      }

      const result = await userCollection.insertOne({
        name,
        email,
        password,
        createdAt: new Date(),
      });
      return res
        .status(200)
        .json({
          success: true,
          message: "User created",
          user: { id: result.insertedId, name, email },
        });
    } catch (error) {
      return handleError(res, error, "Create User Error");
    }
  });

  app.get("/user/:email", async (req: Request, res: Response): Promise<any> => {
    try {
      const { email } = req.params;
      if (!email)
        return res
          .status(400)
          .json({ success: false, message: "Email is required" });
      if (!userCollection)
        return res
          .status(503)
          .json({ success: false, message: "Database not available" });

      const user = await userCollection.findOne({ email });
      return res.status(200).json({ success: true, user });
    } catch (error) {
      return handleError(res, error, "Get User Error");
    }
  });

  // --- EMAIL ---
  app.post("/send-email", async (req: Request, res: Response): Promise<any> => {
    try {
      const { name, email } = req.body.data || req.body;
      if (!email)
        return res
          .status(400)
          .json({ success: false, message: "Email is required" });

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

      return res
        .status(200)
        .json({ success: true, message: "Welcome email sent successfully" });
    } catch (error) {
      return handleError(res, error, "Mail Error");
    }
  });

  // --- SCANNER ---
  app.post(
    "/scanner-data",
    async (req: Request, res: Response): Promise<any> => {
      try {
        const parsed = scanSchema.safeParse(req.body);
        if (!parsed.success)
          return res
            .status(400)
            .json({ success: false, errors: parsed.error.flatten() });

        const { type, value } = parsed.data;
        const { userEmail } = req.body;
        if (!userEmail)
          return res
            .status(400)
            .json({ success: false, message: "User email is required" });
        if (!scanHistoryCollection)
          return res
            .status(503)
            .json({ success: false, message: "Database not available" });

        const [googleResult, virusTotalResult] = await Promise.all([
          checkUrlWithGoogle(value).catch(() => null),
          checkUrlWithVirusTotal(value).catch(() => ({
            stats: { malicious: 0, suspicious: 0 },
          })),
        ]);

        const malicious = virusTotalResult.stats.malicious || 0;
        const suspicious = virusTotalResult.stats.suspicious || 0;
        const googleMatches = Array.isArray((googleResult as any)?.matches)
          ? (googleResult as any).matches.length
          : 0;

        const evidenceScore = Math.min(
          (malicious ? 70 : 0) +
            (suspicious ? 20 : 0) +
            (googleMatches ? 60 : 0),
          100,
        );

        let aiResult = {
          isScam: evidenceScore >= 50,
          score: evidenceScore,
          summary:
            googleMatches && !malicious
              ? "Google Safe Browsing detection."
              : evidenceScore >= 50
                ? "Potential threat detected."
                : "No threat detected.",
          insights: [
            `VirusTotal malicious: ${malicious}`,
            `VirusTotal suspicious: ${suspicious}`,
            googleMatches
              ? "Google Safe Browsing detected a threat."
              : "Google Safe Browsing found no threat.",
          ],
        };

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
        } catch {
          console.warn("Gemini unavailable, using evidence score.");
        }

        const scanDocument = {
          userEmail,
          type,
          value,
          ...aiResult,
          createdAt: new Date(),
        };
        const inserted = await scanHistoryCollection.insertOne(scanDocument);

        return res
          .status(200)
          .json({
            success: true,
            ...aiResult,
            scanId: inserted.insertedId.toString(),
          });
      } catch (error) {
        return handleError(res, error, "Scanner Route Error");
      }
    },
  );

  // --- SCAN HISTORY ---
  app.get(
    "/scan-history/:email",
    async (req: Request, res: Response): Promise<any> => {
      try {
        const { email } = req.params;
        if (!email)
          return res
            .status(400)
            .json({ success: false, message: "Email is required" });
        if (!scanHistoryCollection)
          return res
            .status(503)
            .json({ success: false, message: "Database not available" });

        const history = await scanHistoryCollection
          .find({ userEmail: email })
          .sort({ createdAt: -1 })
          .toArray();
        return res.status(200).json({ success: true, history });
      } catch (error) {
        return handleError(res, error, "Scan History Error");
      }
    },
  );

  app.delete(
    "/scan-history/:id",
    async (req: Request, res: Response): Promise<any> => {
      try {
        const id = Array.isArray(req.params.id)
          ? req.params.id[0]
          : req.params.id;
        if (!id || !ObjectId.isValid(id))
          return res
            .status(400)
            .json({ success: false, message: "Invalid ID" });
        if (!scanHistoryCollection)
          return res
            .status(503)
            .json({ success: false, message: "Database not available" });

        const result = await scanHistoryCollection.deleteOne({
          _id: new ObjectId(id),
        });
       console.log(result)
        return res
          .status(200)
          .json({ success: true, message: "Deleted successfully", result });
      } catch (error) {
        return handleError(res, error, "Delete Error");
      }
    },
  );

  app.listen(port, () =>
    console.log(`ScamShield server running on port ${port}`),
  );
}

run();
