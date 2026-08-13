import z from "zod";

export const scanSchema = z.object({
  type: z.enum(["url", "email", "phone", "text"]),
  value: z
    .string()
    .trim()
    .min(1, "Input is required")
    .transform((s) => s.toLowerCase()),
});

export type ScanInput = z.infer<typeof scanSchema>;
