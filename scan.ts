import z from "zod";

export const urlSchema = z.object({
  type: z.literal("url"),
  value: z
    .string()
    .trim()
    .min(1, "URL is required")
    .url("Please enter a valid URL")
    .transform((s) => s.toLowerCase()),
});

export const phoneSchema = z.object({
  type: z.literal("phone"),
  value: z
    .string()
    .trim()
    .min(1, "Phone number is required"),
});

export const textSchema = z.object({
  type: z.literal("text"),
  value: z
    .string()
    .trim()
    .min(1, "Text is required"),
});

export const scanSchema = z.discriminatedUnion("type", [
  urlSchema,
  phoneSchema,
  textSchema,
]);

export type ScanInput = z.infer<typeof scanSchema>;