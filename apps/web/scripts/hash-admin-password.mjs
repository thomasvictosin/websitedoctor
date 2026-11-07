import { randomBytes, scryptSync } from "node:crypto";
import { stdin, stdout } from "node:process";

if (!stdin.isTTY || !stdout.isTTY) {
  throw new Error("Run this command in an interactive terminal so the password is not echoed.");
}

stdout.write("Administrator password (min. 12 characters): ");
stdin.setRawMode(true);
stdin.setEncoding("utf8");

let password = "";
stdin.on("data", (character) => {
  if (character === "\u0003") {
    stdout.write("\nCancelled.\n");
    process.exit(1);
  }
  if (character === "\r" || character === "\n") {
    stdin.setRawMode(false);
    stdin.pause();
    stdout.write("\n");
    if (Buffer.byteLength(password) < 12) {
      password = "";
      throw new Error("Password must be at least 12 bytes.");
    }
    const salt = randomBytes(16);
    const derived = scryptSync(password, salt, 64);
    password = "";
    const encodedHash = `scrypt$${salt.toString("base64url")}$${derived.toString("base64url")}`;
    stdout.write(`ADMIN_PASSWORD_HASH="${encodedHash.replaceAll("$", () => "\\$")}"\n`);
    stdout.write("Sign in with the password you just entered, not the hash above.\n");
    return;
  }
  if (character === "\u007f" || character === "\b") {
    password = password.slice(0, -1);
    return;
  }
  password += character;
});
