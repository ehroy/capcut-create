import { fetch as undiciFetch, ProxyAgent, setGlobalDispatcher } from "undici";
import inquirer from "inquirer";
import fs from "fs/promises";
import dotenv from "dotenv";
import { faker } from "@faker-js/faker";
const proxy = process.env.PROXY_URL;
function randomName(len) {
  const chars = "abcdefghijklmnopqrstuvwxyz0987654321";
  return Array.from(
    { length: len },
    () => chars[Math.floor(Math.random() * chars.length)]
  ).join("");
}
// kalau ada proxy, set dispatcher
if (proxy && proxy.trim() !== "") {
  setGlobalDispatcher(new ProxyAgent(proxy));
  console.log("Proxy enabled:", proxy);
} else {
  console.log("No proxy set, using direct connection.");
}
// Load environment variables
dotenv.config();

export function xorOperation(text, key = 5) {
  let result = "";
  for (let i = 0; i < text.length; i++) {
    result += String.fromCharCode(text.charCodeAt(i) ^ key);
  }
  return result;
}

// Colors for console output
const colors = {
  reset: "\x1b[0m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  bright: "\x1b[1m",
  dim: "\x1b[2m",
  bgGreen: "\x1b[42m",
  bgRed: "\x1b[41m",
};

// Icons for different log types
const icons = {
  info: "📋",
  success: "✅",
  warning: "⚠️",
  error: "❌",
  loading: "⏳",
  network: "🌐",
  key: "🔑",
  email: "📧",
  shield: "🛡️",
  rocket: "🚀",
  user: "👤",
  bulk: "🔄",
  save: "💾",
  folder: "📁",
  count: "📊",
};

/**
 * Enhanced logging function with colors and icons
 */
function log(message, type = "info", data = null) {
  const timestamp = new Date().toISOString().split("T")[1].split(".")[0];
  let colorCode = colors.white;
  let icon = icons.info;

  switch (type) {
    case "success":
      colorCode = colors.green;
      icon = icons.success;
      break;
    case "error":
      colorCode = colors.red;
      icon = icons.error;
      break;
    case "warning":
      colorCode = colors.yellow;
      icon = icons.warning;
      break;
    case "loading":
      colorCode = colors.cyan;
      icon = icons.loading;
      break;
    case "network":
      colorCode = colors.blue;
      icon = icons.network;
      break;
    case "security":
      colorCode = colors.magenta;
      icon = icons.shield;
      break;
    case "user":
      colorCode = colors.magenta;
      icon = icons.user;
      break;
    case "bulk":
      colorCode = colors.cyan;
      icon = icons.bulk;
      break;
    case "save":
      colorCode = colors.green;
      icon = icons.save;
      break;
    case "count":
      colorCode = colors.yellow;
      icon = icons.count;
      break;
    default:
      colorCode = colors.white;
      icon = icons.info;
  }

  console.log(
    `${colors.dim}[${timestamp}]${colors.reset} ${icon} ${colorCode}${message}${colors.reset}`
  );

  if (data && typeof data === "object") {
    console.log(`${colors.dim}${JSON.stringify(data, null, 2)}${colors.reset}`);
  } else if (data) {
    console.log(`${colors.dim}${data}${colors.reset}`);
  }
}

/**
 * Configuration and constants
 */
const CONFIG = {
  RETRY: {
    MAX_ATTEMPTS: 10,
    DELAY: 2000,
  },
  FILES: {
    ACCOUNTS_DIR: "./accounts",
    SUCCESS_FILE: "./accounts/successful_accounts.txt",
    FAILED_FILE: "./accounts/failed_accounts.txt",
    LOG_FILE: "./accounts/registration_log.txt",
  },
  ENDPOINTS: {
    BASE_URL: "https://www.capcut.com",
    SEND_CODE: "/passport/web/email/send_code/",
    VERIFY_CODE: "/passport/web/email/register/code_verify/",
    VERIFY_LOGIN: "/passport/web/email/register_verify_login/",
    TRIAL_API:
      "https://commerce-api-sg.capcut.com/commerce/v1/subscription/user_info",
  },
  HEADERS: {
    COMMON: {
      accept: "application/json, text/plain, */*",
      "accept-language": "en-US,en;q=0.9",
      "cache-control": "no-cache",
      origin: "https://www.capcut.com",
      pragma: "no-cache",
      priority: "u=1, i",
      referer: "https://www.capcut.com/id-id/signup",
      "sec-ch-ua":
        '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
      "sec-ch-ua-mobile": "?0",
      "sec-ch-ua-platform": '"Windows"',
      "sec-fetch-dest": "empty",
      "sec-fetch-mode": "cors",
      "sec-fetch-site": "same-origin",
      "user-agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      "x-tt-passport-csrf-token": "a90405b488afd7be16c3bc9c5b9c1ced",
    },
    TRIAL: {
      accept: "application/json, text/plain, */*",
      "accept-language": "en-US,en;q=0.9",
      "app-sdk-version": "48.0.0",
      appid: "348188",
      appvr: "12.4.0",
      "content-type": "application/json",
      "device-time": "1745519401",
      lan: "en",
      loc: "ES",
      origin: "https://www.capcut.com",
      pf: "7",
      priority: "u=1, i",
      referer: "https://www.capcut.com/",
      "sec-ch-ua":
        '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
      "sec-ch-ua-mobile": "?0",
      "sec-ch-ua-platform": '"Windows"',
      "sec-fetch-dest": "empty",
      "sec-fetch-mode": "cors",
      "sec-fetch-site": "same-site",
      sign: "f6b3248e06fc5776ec4551beacfa7382",
      "sign-ver": "1",
      tdid: "",
      "user-agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    },
  },
};

/**
 * File manager for handling account storage
 */
class FileManager {
  static async ensureDirectoryExists() {
    try {
      await fs.access(CONFIG.FILES.ACCOUNTS_DIR);
    } catch {
      await fs.mkdir(CONFIG.FILES.ACCOUNTS_DIR, { recursive: true });
      log("Created accounts directory", "save");
    }
  }

  static async saveSuccessfulAccount(email, password, trialInfo = null) {
    await this.ensureDirectoryExists();
    const timestamp = new Date().toISOString();
    const accountData = `${email}:${password} \n`;

    await fs.appendFile(CONFIG.FILES.SUCCESS_FILE, accountData);
    log(`Account saved: ${email}`, "save");
  }

  static async saveFailedAccount(email, password, error) {
    await this.ensureDirectoryExists();
    const timestamp = new Date().toISOString();
    const accountData = `${timestamp} | ${email}:${password} | Status: FAILED | Error: ${error}\n`;

    await fs.appendFile(CONFIG.FILES.FAILED_FILE, accountData);
    log(`Failed account logged: ${email}`, "warning");
  }

  static async saveLog(message) {
    await this.ensureDirectoryExists();
    const timestamp = new Date().toISOString();
    const logData = `[${timestamp}] ${message}\n`;

    await fs.appendFile(CONFIG.FILES.LOG_FILE, logData);
  }

  static async getAccountCounts() {
    await this.ensureDirectoryExists();

    let successCount = 0;
    let failedCount = 0;

    try {
      const successData = await fs.readFile(CONFIG.FILES.SUCCESS_FILE, "utf-8");
      successCount = successData
        .split("\n")
        .filter((line) => line.trim()).length;
    } catch (error) {
      // File doesn't exist yet
    }

    try {
      const failedData = await fs.readFile(CONFIG.FILES.FAILED_FILE, "utf-8");
      failedCount = failedData.split("\n").filter((line) => line.trim()).length;
    } catch (error) {
      // File doesn't exist yet
    }

    return { successCount, failedCount };
  }
}

/**
 * Cookie helper function
 */
function cookieHelpers(arrayCookie) {
  if (!arrayCookie || !Array.isArray(arrayCookie)) return null;
  return arrayCookie.map((cookie) => cookie.split(";")[0]).join("; ");
}

/**
 * Enhanced HTTP client with better error handling and logging
 */
async function httpRequest(url, options = {}) {
  const {
    body = null,
    headers = {},
    maxRetries = CONFIG.RETRY.MAX_ATTEMPTS,
    retryDelay = CONFIG.RETRY.DELAY,
    requestType = "standard",
  } = options;

  let attempt = 0;

  while (attempt < maxRetries) {
    try {
      attempt++;

      if (attempt > 1) {
        log(`Retry attempt ${attempt}/${maxRetries}`, "warning");
      }

      const requestOptions = {
        method: body ? "POST" : "GET",
        headers: {
          ...CONFIG.HEADERS.COMMON,
          ...headers,
        },
        redirect: "manual",
        body: body || null,
      };

      const response = await fetch(url, requestOptions);
      const contentType = response.headers.get("content-type");
      const cookies = response.headers.getSetCookie();
      const cookie = cookies ? cookieHelpers(cookies) : null;
      const redirect = response.headers.get("location") || null;
      const status = response.status;

      let data;
      if (contentType && contentType.includes("application/json")) {
        data = await response.json();
      } else {
        data = await response.text();
      }

      return { data, cookie, redirect, status, success: true };
    } catch (error) {
      if (attempt >= maxRetries) {
        throw new Error(
          `Request failed after ${maxRetries} attempts: ${error.message}`
        );
      }
      await sleep(retryDelay);
    }
  }
}

/**
 * Trial-specific HTTP client
 */
async function httpRequestTrial(url, options = {}) {
  const { body = null, headers = {} } = options;
  return httpRequest(url, {
    ...options,
    headers: {
      ...CONFIG.HEADERS.TRIAL,
      ...headers,
    },
    requestType: "trial",
  });
}

/**
 * Email service HTTP client
 */
async function httpRequestEmail(url, options = {}) {
  return httpRequest(url, {
    ...options,
    headers: {
      accept: "*/*",
      "accept-language": "en-US,en;q=0.9,id;q=0.8",
      "application-name": "web",
      "application-version": "4.0.0",
      "content-type": "application/json",
      origin: "https://temp-mail.io",
      priority: "u=1, i",
      referer: "https://temp-mail.io/",
      "sec-ch-ua":
        '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
      "sec-ch-ua-mobile": "?0",
      "sec-ch-ua-platform": '"Windows"',
      "sec-fetch-dest": "empty",
      "sec-fetch-mode": "cors",
      "sec-fetch-site": "same-site",
      "user-agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
      "x-cors-header": "iaWg3pchvFx48fY",
      ...options.headers,
    },
  });
}

/**
 * Sleep utility function
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Build URL search parameters
 */
function buildUrlParams(params) {
  const urlParams = new URLSearchParams();
  Object.keys(params).forEach((key) => {
    urlParams.append(key, params[key]);
  });
  return urlParams;
}

/**
 * Get bulk creation settings from user
 */
async function getBulkSettings() {
  log("Configure bulk account creation:", "user");

  const settings = await inquirer.prompt([
    {
      type: "input",
      name: "count",
      message: `${icons.count} How many accounts do you want to create?`,
      validate: (input) => {
        const num = parseInt(input);
        if (isNaN(num) || num < 1 || num > 100) {
          return "Please enter a number between 1 and 100.";
        }
        return true;
      },
      filter: (input) => parseInt(input),
    },
    {
      type: "input",
      name: "delay",
      message: `${icons.loading} Delay between registrations (seconds):`,
      default: "5",
      validate: (input) => {
        const num = parseInt(input);
        if (isNaN(num) || num < 1) {
          return "Please enter a valid delay in seconds (minimum 1).";
        }
        return true;
      },
      filter: (input) => parseInt(input) * 1000,
    },
    {
      type: "confirm",
      name: "continueOnError",
      message: "Continue registration if individual accounts fail?",
      default: true,
    },
  ]);

  log("Bulk settings configured:", "success", settings);
  return settings;
}

/**
 * Main CapCut trial registration process
 */
class CapCutTrialManager {
  constructor() {
    this.cookies = null;
    this.email = null;
    this.password = null;
    this.otp = null;
  }

  async getEmail() {
    log("Getting temporary email...", "loading");
    const domain = await httpRequestEmail(
      "https://api.internal.temp-mail.io/api/v4/domains",
      {
        body: null,
      }
    );
    const names = domain.data.domains.map((d) => d.name);
    const randomDomain = names[Math.floor(Math.random() * names.length)];
    const name =
      faker.internet.displayName().toLocaleLowerCase() +
      randomName(Math.floor(Math.random() * 2) + 8);

    const payload = {
      name: name.replace(/[^a-zA-Z0-9]/g, ""),
      domain: randomDomain,
    };

    const response = await httpRequestEmail(
      "https://api.internal.temp-mail.io/api/v3/email/new",
      {
        body: JSON.stringify(payload),
      }
    );

    if (response.success && response.status === 200) {
      const params = {
        mix_mode: "1",
        email: Buffer.from(xorOperation(response.data.email), "utf-8").toString(
          "hex"
        ),
        password: Buffer.from(
          xorOperation(process.env.DEFAULT_PASSWORD),
          "utf-8"
        ).toString("hex"),
        type: "34",
        fixed_mix_mode: "1",
      };
      const responsecheck = await httpRequest(
        "https://www.capcut.com/passport/web/user/check_email_registered?aid=348188&account_sdk_source=web&sdk_version=2.1.10-tiktok&language=en&verifyFp=verify_meennl7z_ntAqVzl9_c9bp_4ty6_9pw1_7NvATgxAhaMl",
        {
          body: buildUrlParams(params),
        }
      );
      if (responsecheck.data.data.is_registered === 0) {
        this.email = response.data.email;
        this.password = process.env.DEFAULT_PASSWORD || "Kaserinas123@";
        log(`Email obtained: ${this.email}`, "success");
      } else {
        throw new Error("Failed to get temporary email");
      }
    } else {
      throw new Error("Failed to get temporary email");
    }

    return response;
  }

  async getOtp() {
    log("Waiting for OTP email...", "loading");
    let response;
    let attempts = 0;
    const maxAttempts = 30; // 1 minute timeout

    do {
      response = await httpRequestEmail(
        `https://api.internal.temp-mail.io/api/v3/email/${this.email}/messages`
      );

      if (response.data && response.data.length > 0) {
        break;
      }

      attempts++;
      if (attempts >= maxAttempts) {
        throw new Error("Timeout waiting for OTP email");
      }

      await sleep(2000);
    } while (response.data.length <= 0);

    if (response.success && response.status === 200) {
      const match = response.data[0].subject.match(/([A-Z0-9]{6})$/);
      if (match) {
        this.otp = match[1];
        log(`OTP received: ${this.otp}`, "success");
      } else {
        throw new Error("Could not extract OTP from email");
      }
    } else {
      throw new Error("Failed to get OTP from email");
    }

    return response;
  }

  async fetchInitialPage() {
    const response = await httpRequest(CONFIG.ENDPOINTS.BASE_URL);
    this.cookies = response.cookie;
    return response;
  }

  async sendVerificationCode() {
    const params = {
      mix_mode: "1",
      email: Buffer.from(xorOperation(this.email), "utf-8").toString("hex"),
      password: Buffer.from(xorOperation(this.password), "utf-8").toString(
        "hex"
      ),
      type: "34",
      fixed_mix_mode: "1",
    };

    const url =
      "https://www.capcut.com/passport/web/email/send_code/?aid=348188&account_sdk_source=web&language=id-ID&verifyFp=verify_m63ct5o9_iA1paegq_5fJV_4xc1_9OWa_5FBqFem2oe3u&check_region=1";
    const response = await httpRequest(url, {
      body: buildUrlParams(params),
      headers: { cookie: this.cookies },
    });

    this.cookies = response.cookie || this.cookies;

    if (response.status !== 200) {
      throw new Error(
        `Failed to send verification code: ${
          response.data?.message || "Unknown error"
        }`
      );
    }

    return response;
  }

  async verifyCode(otp) {
    const params = {
      mix_mode: "1",
      email: Buffer.from(xorOperation(this.email), "utf-8").toString("hex"),
      code: Buffer.from(xorOperation(otp), "utf-8").toString("hex"),
      type: "34",
      fixed_mix_mode: "1",
    };

    const url =
      CONFIG.ENDPOINTS.BASE_URL +
      CONFIG.ENDPOINTS.VERIFY_CODE +
      "?aid=573081&account_sdk_source=web&passport_jssdk_version=1.0.7-beta.2&language=en&verifyFp=verify_m9vlaygx_BMtaVjBT_Ea3T_40gt_9aP1_xNdYVFHgpZrn&check_region=1";

    const response = await httpRequest(url, {
      body: buildUrlParams(params),
      headers: { cookie: this.cookies },
    });

    if (response.status !== 200 || !response.data?.data?.email_ticket) {
      throw new Error("OTP verification failed");
    }

    return response;
  }

  async completeRegistration(otp) {
    const params = {
      mix_mode: "1",
      email: Buffer.from(xorOperation(this.email), "utf-8").toString("hex"),
      code: Buffer.from(xorOperation(otp), "utf-8").toString("hex"),
      password: Buffer.from(xorOperation(this.password), "utf-8").toString(
        "hex"
      ),
      type: "34",
      birthday: "1998-02-06",
      force_user_region: "ID",
      biz_param: '{"invite_code":"HnxC0b95636945"}',
      check_region: "1",
      fixed_mix_mode: "1",
    };

    const url =
      "https://www.capcut.com/passport/web/email/register_verify_login/?aid=348188&account_sdk_source=web&language=id-ID&verifyFp=verify_m63ct5o9_iA1paegq_5fJV_4xc1_9OWa_5FBqFem2oe3u&check_region=1";

    const response = await httpRequest(url, {
      body: buildUrlParams(params),
      headers: { cookie: this.cookies },
    });
    this.cookies = response.cookie || this.cookies;

    if (response.status !== 200) {
      throw new Error("Registration completion failed");
    }
    console.log(response);
    return response;
  }

  async applyTrial() {
    const payload = { aid: "348188", scene: "vip" };

    const response = await httpRequestTrial(CONFIG.ENDPOINTS.TRIAL_API, {
      body: JSON.stringify(payload),
      headers: { cookie: this.cookies },
    });

    if (!response.success || response.status !== 200) {
      throw new Error("Trial application failed");
    }

    return response;
  }

  async registerSingle() {
    try {
      await this.getEmail();
      await this.fetchInitialPage();
      await this.sendVerificationCode();
      await this.getOtp();

      //   const verifyResponse = await this.verifyCode(this.otp);
      await this.completeRegistration(this.otp);
      const trialResponse = await this.applyTrial();

      // Save successful account
      await FileManager.saveSuccessfulAccount(
        this.email,
        this.password,
        trialResponse.data
      );

      log(`✅ Account created successfully: ${this.email}`, "success");
      return { success: true, email: this.email, password: this.password };
    } catch (error) {
      // Save failed account
      await FileManager.saveFailedAccount(
        this.email || "Unknown",
        this.password || "Unknown",
        error.message
      );

      log(`❌ Account creation failed: ${error.message}`, "error");
      return { success: false, error: error.message, email: this.email };
    }
  }
}

/**
 * Bulk registration manager
 */
class BulkRegistrationManager {
  constructor(settings) {
    this.settings = settings;
    this.results = {
      total: 0,
      successful: 0,
      failed: 0,
      accounts: [],
    };
  }

  async start() {
    log(
      `🚀 Starting bulk registration for ${this.settings.count} accounts`,
      "bulk"
    );
    await FileManager.saveLog(
      `Started bulk registration for ${this.settings.count} accounts`
    );

    for (let i = 1; i <= this.settings.count; i++) {
      log(
        `\n${colors.bgGreen}${colors.bright}=== Account ${i}/${this.settings.count} ===${colors.reset}`,
        "count"
      );

      const manager = new CapCutTrialManager();
      const result = await manager.registerSingle();

      this.results.total++;
      if (result.success) {
        this.results.successful++;
      } else {
        this.results.failed++;

        if (!this.settings.continueOnError) {
          log(
            "Stopping bulk registration due to error and continueOnError=false",
            "error"
          );
          break;
        }
      }

      this.results.accounts.push(result);

      // Show current stats
      const counts = await FileManager.getAccountCounts();
      log(
        `Progress: ${i}/${this.settings.count} | Success: ${this.results.successful} | Failed: ${this.results.failed}`,
        "count"
      );
      log(
        `Total saved - Success: ${counts.successCount} | Failed: ${counts.failedCount}`,
        "count"
      );

      // Delay between registrations (except for the last one)
      if (i < this.settings.count) {
        log(
          `Waiting ${
            this.settings.delay / 1000
          } seconds before next registration...`,
          "loading"
        );
        await sleep(this.settings.delay);
      }
    }

    await this.showFinalResults();
  }

  async showFinalResults() {
    const counts = await FileManager.getAccountCounts();

    console.log("\n" + "=".repeat(60));
    log("🎊 BULK REGISTRATION COMPLETED!", "success");
    console.log("=".repeat(60));

    log(`Total accounts processed: ${this.results.total}`, "count");
    log(`Successful registrations: ${this.results.successful}`, "success");
    log(`Failed registrations: ${this.results.failed}`, "error");
    log(
      `Success rate: ${(
        (this.results.successful / this.results.total) *
        100
      ).toFixed(2)}%`,
      "count"
    );

    console.log("\n📁 File locations:");
    log(`Successful accounts: ${CONFIG.FILES.SUCCESS_FILE}`, "save");
    log(`Failed accounts: ${CONFIG.FILES.FAILED_FILE}`, "save");
    log(`Registration log: ${CONFIG.FILES.LOG_FILE}`, "save");

    console.log("\n📊 Total saved accounts:");
    log(`Total successful: ${counts.successCount}`, "success");
    log(`Total failed: ${counts.failedCount}`, "error");

    await FileManager.saveLog(
      `Bulk registration completed. Total: ${this.results.total}, Success: ${this.results.successful}, Failed: ${this.results.failed}`
    );
  }
}

/**
 * Main menu
 */
async function showMainMenu() {
  const { action } = await inquirer.prompt([
    {
      type: "list",
      name: "action",
      message: "What would you like to do?",
      choices: [
        { name: "🔄 Create bulk accounts", value: "bulk" },
        { name: "👤 Create single account", value: "single" },
        { name: "📊 Show account statistics", value: "stats" },
        { name: "❌ Exit", value: "exit" },
      ],
    },
  ]);

  return action;
}

/**
 * Show account statistics
 */
async function showStats() {
  log("📊 Loading account statistics...", "loading");

  const counts = await FileManager.getAccountCounts();

  console.log("\n" + "=".repeat(50));
  log("📊 ACCOUNT STATISTICS", "count");
  console.log("=".repeat(50));

  log(`Successful accounts: ${counts.successCount}`, "success");
  log(`Failed accounts: ${counts.failedCount}`, "error");
  log(`Total attempts: ${counts.successCount + counts.failedCount}`, "count");

  if (counts.successCount + counts.failedCount > 0) {
    const successRate = (
      (counts.successCount / (counts.successCount + counts.failedCount)) *
      100
    ).toFixed(2);
    log(`Success rate: ${successRate}%`, "count");
  }

  console.log("\n📁 File locations:");
  log(`Successful accounts: ${CONFIG.FILES.SUCCESS_FILE}`, "save");
  log(`Failed accounts: ${CONFIG.FILES.FAILED_FILE}`, "save");
  log(`Registration log: ${CONFIG.FILES.LOG_FILE}`, "save");
}

/**
 * Initialize and run the application
 */
async function main() {
  try {
    // Check if DEFAULT_PASSWORD is set in environment
    if (!process.env.DEFAULT_PASSWORD) {
      log("⚠️ DEFAULT_PASSWORD not found in environment variables", "warning");
      log(
        "Please create a .env file with DEFAULT_PASSWORD=your_password",
        "info"
      );
      log("Using default password: Kaserinas123@", "warning");
    }

    log("🚀 CapCut Bulk Account Creator", "rocket");

    while (true) {
      console.log("\n");
      const action = await showMainMenu();

      switch (action) {
        case "bulk":
          const settings = await getBulkSettings();
          const bulkManager = new BulkRegistrationManager(settings);
          await bulkManager.start();
          break;

        case "single":
          log("Creating single account...", "loading");
          const manager = new CapCutTrialManager();
          await manager.registerSingle();
          break;

        case "stats":
          await showStats();
          break;

        case "exit":
          log("👋 Goodbye!", "success");
          process.exit(0);

        default:
          log("Invalid action", "error");
      }
    }
  } catch (error) {
    log(`Application failed: ${error.message}`, "error");
    process.exit(1);
  }
}

// Run the application
main();
