import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { authConfig } from "./auth.config";
import { z } from "zod";
import type { User } from "@/app/lib/definitions";
import bcrypt from "bcrypt";
import postgres from "postgres";

const sql = postgres(process.env.POSTGRES_URL!, { ssl: "require" });

async function getUser(email: string): Promise<User | undefined> {
  try {
    console.log("Attempting to fetch user with email:", email);
    const user = await sql<User[]>`SELECT * FROM users WHERE email=${email}`;
    console.log("User fetch result:", user);
    return user[0];
  } catch (error) {
    console.error("Failed to fetch user:", error);
    throw new Error("Failed to fetch user.");
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        try {
          const parsedCredentials = z
            .object({ email: z.string().email(), password: z.string().min(6) })
            .safeParse(credentials);
          if (parsedCredentials.success) {
            const { email, password } = parsedCredentials.data;
            console.log("Attempting to authenticate user:", email);
            const user = await getUser(email);
            if (!user) {
              console.log("User not found");
              return null;
            }
            console.log("user", user);
            const passwordsMatch = await bcrypt.compare(
              password,
              user.password
            );
            console.log("Password match result:", passwordsMatch);

            if (passwordsMatch) return user;
          }

          console.log("Invalid credentials");
          return null;
        } catch (error) {
          console.error("Authentication error:", error);
          return null;
        }
      },
    }),
  ],
});
