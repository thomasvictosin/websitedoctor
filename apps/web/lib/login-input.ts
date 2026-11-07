import { z } from "zod";

const loginEmailSchema = z.string().max(254).refine(
  (value) => value.toLowerCase() === "admin@localhost" || z.email().safeParse(value).success,
);

export const loginSchema = z.object({
  email: loginEmailSchema.optional(),
  password: z.string().max(1024),
});
