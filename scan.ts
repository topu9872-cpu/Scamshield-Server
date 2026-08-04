import z from "zod";

export const scanSchema = z.object({
  type: z.enum(["url", "email", "phone", "text"]),
  value: z.string().trim().toLowerCase().min(1, "Input is required"),
});

export type ScanInput = z.infer<typeof scanSchema>;
