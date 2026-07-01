import puppeteer from 'puppeteer'
import express from 'express'
import rateLimit from 'express-rate-limit'

const app = express()
app.use(express.json())
app.set('trust proxy', 'loopback')

app.use(
    '/visit', rateLimit({
        windowMs: 3 * 60 * 1000,
        max: 10,
        standardHeaders: true,
        legacyHeaders: false,
        message: { error: 'Too many requests, try again later' },
    })
)

const port = process.env.PORT || 3001
const host = process.env.HOST || '127.0.0.1'
const APP_URL = process.env.APP_URL || 'http://localhost/'
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin'
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin_password_change_me'
const sleep = ms => new Promise(r => setTimeout(r, ms));

console.log(`URL: ${APP_URL}`)

async function loginAsAdmin(page) {
    const loginUrl = new URL('/login', APP_URL).toString()
    await page.goto(loginUrl, { waitUntil: 'networkidle2' })

    await page.type('input[name="username"]', ADMIN_USERNAME)
    await page.type('input[name="password"]', ADMIN_PASSWORD)

    await Promise.all([
        page.waitForNavigation({ waitUntil: 'networkidle2' }),
        page.click('button[type="submit"]'),
    ])

    const body = await page.evaluate(() => document.body.innerText)
    if (!body.includes('Logout')) {
        throw new Error('Admin login failed')
    }
}

async function visit(url) {
    let browser
    let ctx

    try {
        const browserArgs = [
            '--no-sandbox',
            '--disable-background-networking',
            '--disable-default-apps',
            '--disable-extensions',
            '--disable-gpu',
            '--disable-sync',
            '--disable-translate',
            '--hide-scrollbars',
            '--metrics-recording-only',
            '--mute-audio',
            '--no-first-run',
            '--safebrowsing-disable-auto-update',
            '--disable-dev-shm-usage',
        ]

        browser = await puppeteer.launch({
            headless: "headless",
            args: browserArgs,
        })

        ctx = await browser.createBrowserContext()

        const page = await ctx.newPage()
        await loginAsAdmin(page)

        await sleep(1000)
        await page.close()

        const newPage = await ctx.newPage()
        await newPage.goto(url, {
            waitUntil: 'networkidle2',
            timeout: 30000,
        })

        await sleep(5 * 60 * 1000)
    } catch (err) {
        console.log(err)
    } finally {
        if (browser) {
            await browser.close()
        }

        console.log(`[*] Done visiting -> ${url}`)
    }
}

app.get('/visit', async (req, res) => {
    let {url} = req.query
    if(
        (typeof url !== 'string') || (url === undefined) ||
        (url === '') || (!url.startsWith('http'))
    ){
        return res.status(400).send({error: "Invalid url"})
    }

    console.log(`[*] Queued visit -> ${url}`)
    visit(url).catch((e) => {
        console.error(`[-] Error visiting -> ${url}: ${e.message}`)
    })
    return res.sendStatus(200)
})

app.listen(port, host, async () => {
    console.log(`[*] Listening on ${host}:${port}`)
})
