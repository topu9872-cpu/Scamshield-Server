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
import { analyzeWithGemini, identifyCompany } from "./gemini.js";
import { checkUrlWithVirusTotal } from "./utils/virusTotal.js";
import {
  scorePhoneRisk,
  scoreUrlRisk,
  scoreTextRisk,
} from "./riskScoring.js";
import {
  extractDomain,
  getCompanyNameFromDomain,
  getWebsiteInfo,
} from "./services/company.js";
import { calculateTrustScore } from "./services/terstScore.js";

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());

const uri = process.env.MONGODB_URI;

if (!uri) {
  throw new Error("MONGODB_URI is required");
}

/* =========================================================
   MONGODB
========================================================= */

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

let isDBConnected = false;

const connectDB = async () => {
  if (isDBConnected && scanHistoryCollection) {
    return;
  }

  await client.connect();

  const db = client.db(
    process.env.MONGODB_DB_NAME?.trim() || "Scamshield",
  );

  userCollection = db.collection("users");
  scanHistoryCollection = db.collection("scan_history");
  blacklistedPhonesCollection = db.collection("blacklisted_phones");

  isDBConnected = true;

  console.log("MongoDB connected successfully");
};

/* =========================================================
   ERROR HANDLER
========================================================= */

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

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get("/", (_req: Request, res: Response) => {
  res.status(200).json({
    success: true,
    message: "ScamShield API is running",
  });
});

/* =========================================================
   USERS
========================================================= */

app.post(
  "/user",
  async (req: Request, res: Response): Promise<any> => {
    try {
      await connectDB();

      const { name, email, password } = req.body;

      if (!email) {
        return res.status(400).json({
          success: false,
          message: "Email is required",
        });
      }

      const existingUser = await userCollection.findOne({ email });

      if (existingUser) {
        return res.status(409).json({
          success: false,
          message: "User already exists",
        });
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
        user: {
          id: result.insertedId,
          name,
          email,
        },
      });
    } catch (error) {
      return handleError(res, error, "Create User Error");
    }
  },
);

app.get(
  "/user/:email",
  async (req: Request, res: Response): Promise<any> => {
    try {
      await connectDB();

      const { email } = req.params;

      if (!email) {
        return res.status(400).json({
          success: false,
          message: "Email is required",
        });
      }

      const user = await userCollection.findOne({ email });

      return res.status(200).json({
        success: true,
        user,
      });
    } catch (error) {
      return handleError(res, error, "Get User Error");
    }
  },
);

/* =========================================================
   EMAIL
========================================================= */

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

app.post(
  "/send-email",
  async (req: Request, res: Response): Promise<any> => {
    try {
      const { name, email } = req.body.data || req.body;

      if (!email) {
        return res.status(400).json({
          success: false,
          message: "Email is required",
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
              Welcome to ScamShield, ${name}!
            </h2>

            <p>
              Hi <strong>${name}</strong>,
            </p>

            <p>
              Thank you for joining <strong>ScamShield</strong>.
              Your account has been successfully created.
            </p>

            <p>
              You can now sign in to your account and explore
              security features designed to help protect you
              from online scams and cyber threats.
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
    } catch (error) {
      return handleError(res, error, "Mail Error");
    }
  },
);

/* =========================================================
   SCANNER
========================================================= */

app.post(
  "/scanner-data",
  async (req: Request, res: Response): Promise<any> => {
    try {
      await connectDB();

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

      let googleResult: any = null;
      let virusTotalResult: any = null;

      let malicious = 0;
      let suspicious = 0;
      let googleMatches = 0;
      let isKnownScam = false;

      let company = null;

      /* URL COMPANY INFORMATION */

      if (type === "url") {
        const domain = extractDomain(value);

        if (domain) {
          const websiteInfo = await getWebsiteInfo(value);

          company = {
            domain,
            name: getCompanyNameFromDomain(domain),
            website: value,
            title: websiteInfo?.title ?? null,
            description: websiteInfo?.description ?? null,
            image: websiteInfo?.image ?? null,
          };
        }
      }

      /* URL CHECK */

      if (type === "url") {
        const [
          googleResponse,
          virusTotalResponse,
        ] = await Promise.all([
          checkUrlWithGoogle(value).catch((error) => {
            console.error(
              "Google Safe Browsing error:",
              error,
            );

            return {
              matches: [],
            };
          }),

          checkUrlWithVirusTotal(value).catch(
            (error: unknown) => {
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
            },
          ),
        ]);

        googleResult = googleResponse ?? {
          matches: [],
        };

        virusTotalResult =
          virusTotalResponse ?? {
            stats: {
              malicious: 0,
              suspicious: 0,
              harmless: 0,
              undetected: 0,
            },
          };

        malicious = Number(
          virusTotalResult.stats?.malicious ?? 0,
        );

        suspicious = Number(
          virusTotalResult.stats?.suspicious ?? 0,
        );

        googleMatches = Array.isArray(
          googleResult.matches,
        )
          ? googleResult.matches.length
          : 0;
      }

      /* PHONE BLACKLIST */

      if (type === "phone") {
        const cleanPhone = value.replace(/\D/g, "");

        try {
          const blacklistedEntry =
            await blacklistedPhonesCollection.findOne({
              phone: cleanPhone,
            });

          isKnownScam = Boolean(blacklistedEntry);
        } catch (error) {
          console.error(
            "Phone blacklist error:",
            error,
          );
        }
      }

      /* LOCAL RISK SCORE */

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

        if (isKnownScam) {
          evidenceScore = Math.max(
            evidenceScore,
            80,
          );
        }
      }

      if (type === "text") {
        evidenceScore = scoreTextRisk(
          type,
          value,
          malicious,
          suspicious,
        );
      }

      /* FALLBACK */

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

      /* GEMINI */

      let finalResult = fallbackResult;

      try {
        const gemini = await analyzeWithGemini(
          type,
          value,
          googleResult,
          virusTotalResult,
          context,
        );

        const geminiScore = Math.max(
          0,
          Math.min(
            100,
            Math.round(
              Number(gemini.score) || 0,
            ),
          ),
        );

        const finalScore = Math.max(
          evidenceScore,
          geminiScore,
        );

        finalResult = {
          isScam: finalScore >= 60,

          score: finalScore,

          summary:
            gemini.summary ||
            fallbackResult.summary,

          insights:
            Array.isArray(gemini.insights) &&
            gemini.insights.length
              ? gemini.insights
                  .map(String)
                  .slice(0, 3)
              : fallbackResult.insights,
        };
      } catch (error) {
        console.error(
          "GEMINI FAILED:",
          error,
        );
      }

      /* FINAL DOCUMENT */

      const finalScore = Math.max(
        0,
        Math.min(
          100,
          Math.round(finalResult.score),
        ),
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

        insights: finalResult.insights
          .map(String)
          .slice(0, 3),

        createdAt: new Date(),
      };

      /* SAVE HISTORY */

      let scanId: string | null = null;

      try {
        const inserted =
          await scanHistoryCollection.insertOne(
            scanDocument,
          );

        scanId =
          inserted.insertedId.toString();
      } catch (error) {
        console.error(
          "Failed to save scan history:",
          error,
        );
      }

      /* RESPONSE */

      return res.status(200).json({
        success: true,
        isScam: scanDocument.isScam,
        score: scanDocument.score,
        summary: scanDocument.summary,
        insights: scanDocument.insights,
        scanId,
        company,
      });
    } catch (error) {
      return handleError(
        res,
        error,
        "Scanner Route Error",
      );
    }
  },
);

/* =========================================================
   SCAN HISTORY
========================================================= */

app.get(
  "/scan-history/:email",
  async (
    req: Request,
    res: Response,
  ): Promise<any> => {
    try {
      await connectDB();

      const { email } = req.params;

      const page = Math.max(
        1,
        Number(req.query.page ?? 1),
      );

      const limit = Math.min(
        50,
        Math.max(
          1,
          Number(req.query.limit ?? 8),
        ),
      );

      const sortBy =
        (req.query.sortBy as string) ||
        "createdAt";

      const sortOrder =
        (req.query.sortOrder as string) ===
        "asc"
          ? 1
          : -1;

      const search =
        (req.query.search as string) || "";

      const filter =
        (req.query.filter as string) || "All";

      if (!email) {
        return res.status(400).json({
          success: false,
          message: "Email is required",
        });
      }

      const query: any = {
        userEmail: email,
      };

      if (search) {
        query.$or = [
          {
            value: {
              $regex: search,
              $options: "i",
            },
          },
          {
            type: {
              $regex: search,
              $options: "i",
            },
          },
        ];
      }

      if (filter !== "All") {
        if (filter === "Safe") {
          query.score = {
            $lte: 40,
          };
        } else if (
          filter === "Suspicious"
        ) {
          query.score = {
            $gt: 40,
            $lte: 70,
          };
        } else if (
          filter === "Scam Detected"
        ) {
          query.isScam = true;
        }
      }

      const sortQuery: Record<
        string,
        1 | -1
      > = {};

      sortQuery[sortBy] = sortOrder;

      const skip = (page - 1) * limit;

      const [
        history,
        total,
      ] = await Promise.all([
        scanHistoryCollection
          .find(query)
          .sort(sortQuery)
          .skip(skip)
          .limit(limit)
          .toArray(),

        scanHistoryCollection.countDocuments(
          query,
        ),
      ]);

      return res.status(200).json({
        success: true,
        history,
        page,
        limit,
        total,
        totalPages: Math.ceil(
          total / limit,
        ),
      });
    } catch (error) {
      return handleError(
        res,
        error,
        "Scan History Error",
      );
    }
  },
);

/* =========================================================
   COMPANY DETAILS
========================================================= */

app.get(
  "/company-details",
  async (
    req: Request,
    res: Response,
  ) => {
    try {
      const { url } = req.query;

      if (
        !url ||
        typeof url !== "string"
      ) {
        return res.status(400).json({
          success: false,
          message: "URL is required",
        });
      }

      const domain = extractDomain(url);

      if (!domain) {
        return res.status(400).json({
          success: false,
          message: "Invalid URL",
        });
      }

      console.log(
        "DOMAIN:",
        domain,
      );

      const domainCompanyName =
        getCompanyNameFromDomain(
          domain,
        );

      const website =
        await getWebsiteInfo(url).catch(
          () => null,
        );

      const aiCompanyName =
        await identifyCompany(
          domain,
          website?.title,
          website?.description,
        ).catch((error) => {
          console.error(
            "Company identification error:",
            error,
          );

          return null;
        });

      const finalCompanyName =
        typeof aiCompanyName ===
          "string" &&
        aiCompanyName.trim()
          ? aiCompanyName.trim()
          : domainCompanyName;

      const trustScore =
        calculateTrustScore({
          malicious: 0,
          suspicious: 0,
          googleMatches: 0,
          https: url.startsWith(
            "https://",
          ),
          hasMetadata: Boolean(
            website?.title ||
              website?.description,
          ),
        });

      return res.json({
        success: true,

        company: {
          name: finalCompanyName,

          domain,

          title:
            website?.title ?? null,

          description:
            website?.description ??
            null,

          image:
            website?.image ?? null,

          website: `https://${domain}`,

          trustScore,

          isScam: false,
        },
      });
    } catch (error) {
      console.error(
        "Company Details Error:",
        error,
      );

      return handleError(
        res,
        error,
        "Company Details Error",
      );
    }
  },
);

/* =========================================================
   DELETE SCAN HISTORY
========================================================= */

app.delete(
  "/scan-history/:id",
  async (
    req: Request,
    res: Response,
  ): Promise<any> => {
    try {
      await connectDB();

      const id = Array.isArray(
        req.params.id,
      )
        ? req.params.id[0]
        : req.params.id;

      if (
        !id ||
        !ObjectId.isValid(id)
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid ID",
        });
      }

      const result =
        await scanHistoryCollection.deleteOne(
          {
            _id: new ObjectId(id),
          },
        );

      return res.status(200).json({
        success: true,
        message: "Deleted successfully",
        result,
      });
    } catch (error) {
      return handleError(
        res,
        error,
        "Delete Error",
      );
    }
  },
);

/* =========================================================
   MONTHLY USER ACTIVITY
========================================================= */

app.get(
  "/monthly-user-activity",
  async (
    req: Request,
    res: Response,
  ) => {
    try {
      /*
       * IMPORTANT:
       * Connect to MongoDB before using
       * scanHistoryCollection.
       */

      await connectDB();

      const { email } = req.query;

      /* VALIDATE EMAIL */

      if (
        !email ||
        typeof email !== "string"
      ) {
        return res.status(400).json({
          success: false,
          message: "Email is required",
        });
      }

      /* DATE RANGE */

      const now = new Date();

      const startDate = new Date(
        now.getFullYear(),
        now.getMonth() - 5,
        1,
      );

      /* LAST 6 MONTHS */

      const months = Array.from(
        { length: 6 },
        (_, index) => {
          const date = new Date(
            now.getFullYear(),
            now.getMonth() -
              (5 - index),
            1,
          );

          return {
            year:
              date.getFullYear(),

            month:
              date.getMonth() + 1,

            monthName:
              date.toLocaleString(
                "en-US",
                {
                  month: "short",
                },
              ),

            activity: 0,
          };
        },
      );

      /* GET USER ACTIVITY */

      const results =
        await scanHistoryCollection
          .aggregate([
            {
              $match: {
                userEmail: email,

                createdAt: {
                  $gte: startDate,
                  $lte: now,
                },
              },
            },

            {
              $group: {
                _id: {
                  year: {
                    $year:
                      "$createdAt",
                  },

                  month: {
                    $month:
                      "$createdAt",
                  },
                },

                activity: {
                  $sum: 1,
                },
              },
            },

            {
              $sort: {
                "_id.year": 1,
                "_id.month": 1,
              },
            },
          ])
          .toArray();

      /* MERGE */

      results.forEach((item) => {
        const month =
          months.find(
            (m) =>
              m.year ===
                item._id.year &&
              m.month ===
                item._id.month,
          );

        if (month) {
          month.activity =
            item.activity;
        }
      });

      /* RESPONSE */

      return res.status(200).json({
        success: true,

        email,

        data: months.map(
          (month) => ({
            month:
              month.monthName,

            activity:
              month.activity,
          }),
        ),
      });
    } catch (error) {
      console.error(
        "Monthly user activity error:",
        error,
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to fetch user activity",
      });
    }
  },
);

/* =========================================================
   VERCEL
========================================================= */

export default app;