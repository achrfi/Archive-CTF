const express = require("express");
const puppeteer = require("puppeteer-core");

const app = express();

const wordpressLoginUrl = process.env.CHALL_SERVER_URL || "http://127.0.0.1:9100";
const editorUser = process.env.WORDPRESS_EDITOR_USER;
const editorPassword = process.env.WORDPRESS_EDITOR_PASSWORD;
const chromiumPath = process.env.PUPPETEER_EXECUTABLE_PATH || "/usr/bin/chromium";

let activeVisits = 0;
const MAX_PARALLEL_VISITS = 25;

app.use(express.json());

function isAllowedTarget(urlString) {
  try {
    const parsed = new URL(urlString);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

async function loginAndVisit(targetUrl) {
  const browser = await puppeteer.launch({
    executablePath: chromiumPath,
    headless: "new",
    ignoreHTTPSErrors: true,
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      "--window-size=1440,900",
      "--ignore-certificate-errors"
    ]
  });

  try {
    const page = await browser.newPage();
    await page.goto(`${wordpressLoginUrl}/wp-login.php`, {
      waitUntil: "networkidle2",
      timeout: 10000
    });

    await page.type("#user_login", editorUser);
    await page.type("#user_pass", editorPassword);
    await Promise.all([
      page.click("#wp-submit"),
      page.waitForNavigation({ waitUntil: "networkidle2", timeout: 10000 })
    ]);

    await page.goto(targetUrl, {
      waitUntil: "networkidle2",
      timeout: 10000
    });

  } finally {
    await browser.close();
  }
}

app.get("/", (_req, res) => {
  res.json({
    ok: true,
    message: "Submit /visit?url=http://target or POST /visit with {\"url\":\"http://target\"}"
  });
});

async function handleVisit(req, res) {
  const targetUrl = req.method === "POST" ? req.body?.url : req.query.url;

  if (!editorUser || !editorPassword) {
    return res.status(500).json({ ok: false, error: "Bot credentials are not configured" });
  }

  if (!targetUrl || !isAllowedTarget(targetUrl)) {
    return res.status(400).json({ ok: false, error: "A valid absolute http(s) URL is required" });
  }

  if (activeVisits >= MAX_PARALLEL_VISITS) {
    return res.status(429).json({ ok: false, error: "Bot is busy" });
  }

  activeVisits++;

  try {
    await loginAndVisit(targetUrl);
    return res.json({ ok: true, visited: targetUrl });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      error: "Bot visit failed",
      detail: error.message
    });
  } finally {
    activeVisits--;
  }
}

app.get("/visit", handleVisit);
app.post("/visit", handleVisit);

app.listen(3000, "0.0.0.0", () => {
  console.log(`bot listening on :3000`);
});
