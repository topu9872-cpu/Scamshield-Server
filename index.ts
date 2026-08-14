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
import { scoreUrlRisk } from "./riskScoring.js";
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
  return res.status(500).json({
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
      return res.status(200).json({
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

        if (!scanHistoryCollection) {
          return res.status(503).json({
            success: false,
            message: "Database not available",
          });
        }

        let googleResult: unknown = null;
        let virusTotalResult: unknown = null;

        let malicious = 0;
        let suspicious = 0;
        let googleMatches = 0;

        // ==========================================
        // URL ONLY
        // ==========================================

        if (type === "url") {
          const [googleResponse, virusTotalResponse] = await Promise.all([
            checkUrlWithGoogle(value).catch((error) => {
              console.error("Google Safe Browsing error:", error);
              return null;
            }),

            checkUrlWithVirusTotal(value).catch((error) => {
              console.error("VirusTotal error:", error);

              return {
                stats: {
                  malicious: 0,
                  suspicious: 0,
                },
              };
            }),
          ]);

          googleResult = googleResponse;
          virusTotalResult = virusTotalResponse;

          malicious =
            Number((virusTotalResponse as any)?.stats?.malicious) || 0;

          suspicious =
            Number((virusTotalResponse as any)?.stats?.suspicious) || 0;

          googleMatches = Array.isArray((googleResponse as any)?.matches)
            ? (googleResponse as any).matches.length
            : 0;
        }

        // ==========================================
        // URL EVIDENCE SCORE
        // ==========================================

        const evidenceScore =
          type === "url"
            ? scoreUrlRisk(type, value, malicious, suspicious, googleMatches)
            : 0;

        const buildFallbackResult = () => ({
          isScam: evidenceScore >= 60,
          score: Math.max(0, Math.min(100, evidenceScore)),
          summary:
            evidenceScore >= 60
              ? "Potential phishing or scam pattern detected."
              : evidenceScore >= 40
                ? "Suspicious behavior detected."
                : "No known threat detected.",
          insights: [
            `VirusTotal malicious: ${malicious}`,
            `VirusTotal suspicious: ${suspicious}`,
            googleMatches > 0
              ? "Google Safe Browsing detected a threat."
              : "Google Safe Browsing found no known threat.",
          ],
        });

        let aiResult = buildFallbackResult();

        try {
          const gemini = await analyzeWithGemini(
            type,
            value,
            googleResult,
            virusTotalResult,
          );

          console.log("GEMINI RESULT:", gemini);

          aiResult = {
            isScam: gemini.isScam || evidenceScore >= 60,
            score: Math.max(
              evidenceScore,
              Math.max(0, Math.min(100, Math.round(gemini.score))),
            ),
            summary: gemini.summary || aiResult.summary,
            insights: gemini.insights.map(String).slice(0, 3),
          };
        } catch (error) {
          console.error("GEMINI FAILED:", error);
          aiResult = buildFallbackResult();
          aiResult.isScam = aiResult.isScam || evidenceScore >= 60;
          aiResult.score = Math.max(aiResult.score, evidenceScore);
        }
        // ==========================================
        // FINAL DOCUMENT
        // ==========================================

        const scanDocument = {
          userEmail,
          type,
          value,

          isScam: aiResult.isScam,

          score: Math.max(0, Math.min(100, Math.round(aiResult.score))),

          summary: aiResult.summary,

          insights: aiResult.insights,

          createdAt: new Date(),
        };

        let scanId = null;

        try {
          const inserted = await scanHistoryCollection.insertOne(scanDocument);
          scanId = inserted.insertedId.toString();
        } catch (dbError) {
          console.error("Failed to save scan history:", dbError);
        }

        return res.status(200).json({
          success: true,

          isScam: scanDocument.isScam,

          score: scanDocument.score,

          summary: scanDocument.summary,

          insights: scanDocument.insights,

          scanId,
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
        const page = Math.max(1, Number(req.query.page ?? 1));
        const limit = Math.min(50, Math.max(1, Number(req.query.limit ?? 8)));

        if (!email)
          return res
            .status(400)
            .json({ success: false, message: "Email is required" });
        if (!scanHistoryCollection)
          return res
            .status(503)
            .json({ success: false, message: "Database not available" });

        const skip = (page - 1) * limit;

        const [history, total] = await Promise.all([
          scanHistoryCollection
            .find({ userEmail: email })
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .toArray(),
          scanHistoryCollection.countDocuments({ userEmail: email }),
        ]);

        return res.status(200).json({
          success: true,
          history,
          page,
          limit,
          total,
          totalPages: Math.ceil(total / limit),
        });
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
        console.log(result);
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
