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
import { scorePhoneRisk, scoreUrlRisk, scoreTextRisk } from "./riskScoring.js";

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
let blacklistedPhonesCollection: Collection<any>;

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
    blacklistedPhonesCollection = db.collection("blacklisted_phones");

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

  app.post(
    "/scanner-data",
    async (req: Request, res: Response): Promise<any> => {
      try {
        // ==========================================
        // VALIDATION
        // ==========================================

        const parsed = scanSchema.safeParse(req.body);

        if (!parsed.success) {
          return res.status(400).json({
            success: false,
            errors: parsed.error.flatten(),
          });
        }

        const { type, value } = parsed.data;
        const { userEmail, context = "" } = req.body;

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

        // ==========================================
        // THREAT INTELLIGENCE
        // ==========================================

        let googleResult: any = null;
        let virusTotalResult: any = null;

        let malicious = 0;
        let suspicious = 0;
        let googleMatches = 0;
        let isKnownScam = false;

        // ==========================================
        // URL CHECK
        // ==========================================

        if (type === "url") {
          const [googleResponse, virusTotalResponse] = await Promise.all([
            checkUrlWithGoogle(value).catch((error) => {
              console.error("Google Safe Browsing error:", error);

              return {
                matches: [],
              };
            }),

            checkUrlWithVirusTotal(value).catch((error: unknown) => {
              console.error("VirusTotal error:", error);

              return {
                stats: {
                  malicious: 0,
                  suspicious: 0,
                  harmless: 0,
                  undetected: 0,
                },
                status: "failed",
                analysisId: "",
              };
            }),
          ]);

         googleResult = googleResponse ?? { matches: [] };
virusTotalResult = virusTotalResponse ?? { 
  stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 } 
};

malicious = Number(virusTotalResult.stats?.malicious ?? 0);
suspicious = Number(virusTotalResult.stats?.suspicious ?? 0);

googleMatches = Array.isArray(googleResult.matches)
  ? googleResult.matches.length
  : 0;
        }

        // ==========================================
        // PHONE BLACKLIST
        // ==========================================

        if (type === "phone" && blacklistedPhonesCollection) {
          const cleanPhone = value.replace(/\D/g, "");

          try {
            const blacklistedEntry = await blacklistedPhonesCollection.findOne({
              phone: cleanPhone,
            });

            isKnownScam = Boolean(blacklistedEntry);
          } catch (error) {
            console.error("Phone blacklist error:", error);
          }
        }

        // ==========================================
        // LOCAL RISK SCORE
        // ==========================================

        let evidenceScore = 0;

        if (type === "url") {
          evidenceScore = scoreUrlRisk(
            type,
            value,
            malicious,
            suspicious,
            googleMatches,
          );
        }

        if (type === "phone") {
          evidenceScore = scorePhoneRisk(
            type,
            value,
            malicious,
            suspicious,
            context,
          );

          // Database blacklist is strong evidence
          if (isKnownScam) {
            evidenceScore = Math.max(evidenceScore, 80);
          }
        }

        if (type === "text") {
          evidenceScore = scoreTextRisk(type, value, malicious, suspicious);
        }

        console.log("================================");
        console.log("LOCAL RISK ANALYSIS");
        console.log("Type:", type);
        console.log("Value:", value);
        console.log("Context:", context || "None");
        console.log("Known scam:", isKnownScam);
        console.log("Malicious:", malicious);
        console.log("Suspicious:", suspicious);
        console.log("Google matches:", googleMatches);
        console.log("Evidence score:", evidenceScore);
        console.log("================================");

        // ==========================================
        // FALLBACK
        // ==========================================

        const fallbackResult = {
          isScam: evidenceScore >= 60,

          score: evidenceScore,

          summary:
            evidenceScore >= 80
              ? "High-risk scam or malicious behavior detected."
              : evidenceScore >= 60
                ? "Potential scam or phishing behavior detected."
                : evidenceScore >= 40
                  ? "Some suspicious indicators were detected."
                  : "No strong scam indicators were detected.",

          insights: [
            `Local risk analysis score: ${evidenceScore}%`,

            type === "url"
              ? `VirusTotal malicious: ${malicious}, suspicious: ${suspicious}`
              : type === "phone"
                ? isKnownScam
                  ? "This phone number matched a known threat record."
                  : "No known threat record was found for this phone number."
                : "Behavioral analysis was used for this message.",

            type === "url"
              ? googleMatches > 0
                ? "Google Safe Browsing detected a known threat."
                : "Google Safe Browsing found no known threat."
              : "Contextual analysis was used.",
          ],
        };

        // ==========================================
        // GEMINI
        // ==========================================

        let finalResult = fallbackResult;

        try {
          const gemini = await analyzeWithGemini(
            type,
            value,
            googleResult,
            virusTotalResult,
            context,
          );

          console.log("GEMINI RESULT:", gemini);

          const geminiScore = Math.max(
            0,
            Math.min(100, Math.round(Number(gemini.score) || 0)),
          );

          const finalScore = Math.max(evidenceScore, geminiScore);

          finalResult = {
            isScam: finalScore >= 60,
            score: finalScore,

            summary: gemini.summary || fallbackResult.summary,

            insights:
              Array.isArray(gemini.insights) && gemini.insights.length
                ? gemini.insights.map(String).slice(0, 3)
                : fallbackResult.insights,
          };

          console.log("================================");
          console.log("GEMINI SCORE:", geminiScore);
          console.log("LOCAL SCORE:", evidenceScore);
          console.log("FINAL SCORE:", finalScore);
          console.log("FINAL IS SCAM:", finalScore >= 60);
          console.log("================================");
        } catch (error) {
          console.error("GEMINI FAILED:", error);
        }

        // ==========================================
        // FINAL DOCUMENT
        // ==========================================

        const finalScore = Math.max(
          0,
          Math.min(100, Math.round(finalResult.score)),
        );

        const scanDocument = {
          userEmail,
          type,
          value,

          ...(type === "phone" && {
            context,
          }),

          isScam: finalScore >= 60,
          score: finalScore,

          summary: finalResult.summary,

          insights: finalResult.insights.map(String).slice(0, 3),

          createdAt: new Date(),
        };

        // ==========================================
        // SAVE HISTORY
        // ==========================================

        let scanId: string | null = null;

        try {
          const inserted = await scanHistoryCollection.insertOne(scanDocument);

          scanId = inserted.insertedId.toString();
        } catch (error) {
          console.error("Failed to save scan history:", error);
        }

        // ==========================================
        // RESPONSE
        // ==========================================

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
        
        // Extract query params sent by the frontend
        const sortBy = (req.query.sortBy as string) || "createdAt";
        const sortOrder = (req.query.sortOrder as string) === "asc" ? 1 : -1;
        const search = (req.query.search as string) || "";
        const filter = (req.query.filter as string) || "All";

        if (!email)
          return res
            .status(400)
            .json({ success: false, message: "Email is required" });
        if (!scanHistoryCollection)
          return res
            .status(503)
            .json({ success: false, message: "Database not available" });

        // Build query filter
        const query: any = { userEmail: email };

        if (search) {
          query.$or = [
            { value: { $regex: search, $options: "i" } },
            { type: { $regex: search, $options: "i" } },
          ];
        }

        if (filter !== "All") {
          if (filter === "Safe") query.score = { $lte: 40 };
          else if (filter === "Suspicious") query.score = { $gt: 40, $lte: 70 };
          else if (filter === "Scam Detected") query.isScam = true;
        }

        // Build dynamic sort object
        const sortQuery: Record<string, 1 | -1> = {};
        sortQuery[sortBy] = sortOrder;

        const skip = (page - 1) * limit;

        const [history, total] = await Promise.all([
          scanHistoryCollection
            .find(query)
            .sort(sortQuery)
            .skip(skip)
            .limit(limit)
            .toArray(),
          scanHistoryCollection.countDocuments(query),
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
