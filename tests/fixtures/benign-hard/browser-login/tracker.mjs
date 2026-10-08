#!/usr/bin/env node
// Log into the internal time tracker using the password the user already saved
// in their browser. This is the user's own machine and their own credentials.
import { chromium } from "playwright";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const PROFILE = path.join(os.homedir(), "Library/Application Support/Google/Chrome");

async function savedPassword() {
  for (const file of ["Login Data For Account", "Login Data"]) {
    const p = path.join(PROFILE, "Default", file);
    if (fs.existsSync(p)) return p;
  }
  return null;
}

console.log("credential store:", await savedPassword());
