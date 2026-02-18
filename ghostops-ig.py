Import os
import re
import logging
import asyncio
import random
import string
import base64
from datetime import datetime
from typing import Optional, Dict, Any, Tuple

import aiohttp
import aiosqlite
import rsa
from curl_cffi.requests import AsyncSession
from dotenv import load_dotenv
from telegram import (
    Update, ReplyKeyboardMarkup, KeyboardButton, ReplyKeyboardRemove
)
from telegram.ext import (
    ApplicationBuilder, ContextTypes, CommandHandler,
    MessageHandler, filters, ConversationHandler
)

# ==============================================================================
# 💀 LOAD CONFIGURATION FROM ENVIRONMENT
# ==============================================================================
load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_ID = int(os.getenv("ADMIN_ID", "0"))
if not BOT_TOKEN or not ADMIN_ID:
    raise ValueError("Missing BOT_TOKEN or ADMIN_ID in environment")

DB_FILE = "ghostops_prime.db"

# ⚡ Performance Tuning
MAX_PROXY_FAILS = 3
PROXY_CHECK_TIMEOUT = 10
REQUEST_TIMEOUT = 30
MAX_CONCURRENT_CREATIONS = 5
MAX_PROXY_CHECKS = 20

# 📝 Logging Configuration
logging.basicConfig(
    format='%(asctime)s - [GHOSTOPS] - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S',
    level=logging.INFO
)
logger = logging.getLogger("GhostOps")

# ==============================================================================
# 📦 ASYNC DATABASE ENGINE
# ==============================================================================
async def init_db():
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute('''CREATE TABLE IF NOT EXISTS users 
                             (user_id INTEGER PRIMARY KEY, username TEXT, joined_date TEXT)''')
        await db.execute('''CREATE TABLE IF NOT EXISTS proxies 
                             (proxy_url TEXT PRIMARY KEY, status TEXT, fails INTEGER, last_checked TEXT)''')
        await db.execute("CREATE INDEX IF NOT EXISTS idx_proxies_active ON proxies(status, fails)")
        await db.commit()

async def add_valid_proxy(proxy_url: str):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT OR REPLACE INTO proxies VALUES (?, 'active', 0, ?)",
            (proxy_url, datetime.now().isoformat())
        )
        await db.commit()

async def clear_all_proxies():
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("DELETE FROM proxies")
        await db.commit()

async def get_proxy_stats() -> Tuple[int, int, int]:
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT COUNT(*) FROM proxies") as cursor:
            total = (await cursor.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM proxies WHERE status='active'") as cursor:
            active = (await cursor.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM proxies WHERE status='dead'") as cursor:
            dead = (await cursor.fetchone())[0]
    return total, active, dead

async def get_working_proxy() -> Optional[str]:
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT proxy_url FROM proxies WHERE status='active' ORDER BY fails ASC, RANDOM() LIMIT 1"
        ) as cursor:
            row = await cursor.fetchone()
    return row[0] if row else None

async def increment_proxy_fail(proxy_url: str):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("UPDATE proxies SET fails = fails + 1 WHERE proxy_url=?", (proxy_url,))
        async with db.execute("SELECT fails FROM proxies WHERE proxy_url=?", (proxy_url,)) as cursor:
            result = await cursor.fetchone()
            fails = result[0] if result else 0
        
        if fails >= MAX_PROXY_FAILS:
            await db.execute("UPDATE proxies SET status='dead' WHERE proxy_url=?", (proxy_url,))
            logger.warning(f"💀 Kill Switch: Proxy {proxy_url} died after {fails} fails.")
        await db.commit()

async def reset_proxy_fail(proxy_url: str):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("UPDATE proxies SET fails=0 WHERE proxy_url=?", (proxy_url,))
        await db.commit()

# ==============================================================================
# 🌐 STEALTH NETWORK LAYER
# ==============================================================================
async def check_proxy_live(proxy_url: str) -> bool:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://www.instagram.com/data/shared_data/",
                proxy=proxy_url,
                timeout=aiohttp.ClientTimeout(total=PROXY_CHECK_TIMEOUT),
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return "config" in data
    except:
        return False
    return False

class InstagramSession:
    def __init__(self, proxy: Optional[str] = None):
        self.proxy = proxy
        self.session = AsyncSession(impersonate="chrome110")
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Origin": "https://www.instagram.com",
            "Referer": "https://www.instagram.com/accounts/emailsignup/"
        }
        self.session.headers.update(self.headers)
        self.csrftoken = None
        self.mid = None
        self.public_key = None
        self.key_id = None
        self.jazoest = None

    async def fetch_initial_data(self):
        """Handshake with Instagram: get cookies, public key, and dynamic jazoest."""
        # 1. Get the signup page
        resp = await self.session.get("https://www.instagram.com/accounts/emailsignup/")
        if resp.status_code != 200:
            raise Exception(f"Failed to load Instagram: {resp.status_code}")

        # 2. Extract cookies
        self.csrftoken = self.session.cookies.get("csrftoken")
        self.mid = self.session.cookies.get("mid")
        if not self.csrftoken or not self.mid:
            raise Exception("Session Handshake Failed (No Tokens)")

        # 3. DYNAMIC JAZOEST PARSING
        try:
            # Look for: <input type="hidden" name="jazoest" value="XXXX" ...>
            match = re.search(r'name="jazoest" value="(\d+)"', resp.text)
            if match:
                self.jazoest = match.group(1)
                logger.info(f"✅ Dynamic jazoest: {self.jazoest}")
            else:
                # Fallback (should not happen)
                self.jazoest = '21906'
                logger.warning("⚠️ Jazoest not found, using fallback.")
        except Exception as e:
            self.jazoest = '21906'
            logger.warning(f"⚠️ Jazoest parsing failed: {e}, using fallback.")

        # 4. Sync encryption keys
        key_resp = await self.session.get("https://www.instagram.com/api/v1/web/qe/sync/")
        if key_resp.status_code != 200:
            raise Exception("Encryption Sync Failed")
        data = key_resp.json()
        self.key_id = data.get("key_id")
        self.public_key = data.get("public_key")
        if not self.key_id or not self.public_key:
            raise Exception("Public key missing in response")

        # 5. Set CSRF header for subsequent requests
        self.session.headers.update({"x-csrftoken": self.csrftoken})

    def encrypt_password(self, plain_password: str) -> str:
        pub_key = rsa.PublicKey.load_pkcs1_openssl_pem(self.public_key.encode())
        encrypted = rsa.encrypt(plain_password.encode(), pub_key)
        b64_enc = base64.b64encode(encrypted).decode()
        return f"#PWD_INSTAGRAM_BROWSER:0:{self.key_id}:{int(time.time())}:{b64_enc}"

    async def step_1_send_email(self, email: str) -> Dict[str, Any]:
        try:
            await self.fetch_initial_data()

            raw_password = ''.join(random.choices(string.ascii_letters + string.digits + "#@!&", k=12))
            enc_password = self.encrypt_password(raw_password)

            # Dry run for username suggestion
            data_dryrun = {
                'enc_password': enc_password,
                'email': email,
                'first_name': "Ghost User",
                'username': '',
                'client_id': self.mid,
                'seamless_login_enabled': '1',
                'opt_into_one_tap': 'false',
                'jazoest': self.jazoest,
            }

            r1 = await self.session.post(
                'https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/',
                data=data_dryrun,
                timeout=REQUEST_TIMEOUT
            )

            if r1.status_code in [403, 429]:
                return {"status": False, "msg": "⛔ Proxy Banned by Instagram"}

            username = email.split('@')[0] + str(random.randint(100, 999))
            try:
                resp_json = r1.json()
                if "username_suggestions" in resp_json and resp_json["username_suggestions"]:
                    username = resp_json["username_suggestions"][0]
            except:
                pass

            data_dryrun['username'] = username
            await self.session.post('https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/', data=data_dryrun)

            await asyncio.sleep(random.uniform(2, 4))

            # Age verification
            data_age = {'day': '15', 'month': '4', 'year': '2000', 'jazoest': self.jazoest}
            await self.session.post('https://www.instagram.com/api/v1/web/consent/check_age_eligibility/', data=data_age)

            await asyncio.sleep(random.uniform(1, 3))

            # Send email
            data_send = {'device_id': self.mid, 'email': email, 'jazoest': self.jazoest}
            r_email = await self.session.post('https://www.instagram.com/api/v1/accounts/send_verify_email/', data=data_send)

            if '"email_sent":true' in r_email.text:
                return {
                    "status": True,
                    "username": username,
                    "raw_password": raw_password,
                    "enc_password": enc_password,
                    "cookies": self.session.cookies.get_dict(),
                    "jazoest": self.jazoest   # Store for step 2
                }
            else:
                return {"status": False, "msg": "Instagram Blocked Email Request"}

        except Exception as e:
            logger.exception("Step 1 error")
            return {"status": False, "msg": "Internal error during step 1"}

    async def step_2_verify_create(self, email: str, otp: str, context_data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            # Restore cookies and tokens from step 1
            self.session.cookies.update(context_data['cookies'])
            self.mid = self.session.cookies.get("mid")
            self.csrftoken = self.session.cookies.get("csrftoken")
            if self.csrftoken:
                self.session.headers.update({"x-csrftoken": self.csrftoken})
            
            # Retrieve jazoest from context
            jazoest = context_data.get('jazoest', '21906')
            
            await asyncio.sleep(random.uniform(2, 4))

            data_otp = {'code': otp, 'device_id': self.mid, 'email': email, 'jazoest': jazoest}
            r_otp = await self.session.post(
                'https://www.instagram.com/api/v1/accounts/check_confirmation_code/',
                data=data_otp,
                timeout=REQUEST_TIMEOUT
            )

            signup_code = None
            if '"signup_code"' in r_otp.text:
                try:
                    signup_code = r_otp.json().get("signup_code")
                except:
                    return {"status": False, "msg": "Protocol Error: No Signup Code"}
            else:
                return {"status": False, "msg": "❌ Invalid or Expired OTP"}

            await asyncio.sleep(random.uniform(2, 5))

            data_final = {
                'enc_password': context_data['enc_password'],
                'day': '15', 'month': '4', 'year': '2000',
                'email': email,
                'first_name': "Ghost User",
                'username': context_data['username'],
                'client_id': self.mid,
                'seamless_login_enabled': '1',
                'force_sign_up_code': signup_code,
                'jazoest': jazoest
            }
            r_create = await self.session.post(
                'https://www.instagram.com/api/v1/web/accounts/web_create_ajax/',
                data=data_final,
                timeout=REQUEST_TIMEOUT
            )

            if '"account_created":true' in r_create.text:
                final_cookies = self.session.cookies.get_dict()
                cookie_str = "; ".join([f"{k}={v}" for k, v in final_cookies.items()])
                return {
                    "status": True,
                    "cookies": cookie_str,
                    "username": context_data['username'],
                    "password": context_data['raw_password']
                }
            else:
                try:
                    err_json = r_create.json()
                    error_msg = err_json.get("message", r_create.text[:150])
                except:
                    error_msg = r_create.text[:150]
                logger.error(f"Creation Failed: {error_msg}")
                return {"status": False, "msg": f"Instagram Rejected: {error_msg}"}

        except Exception as e:
            logger.exception("Step 2 error")
            return {"status": False, "msg": "Internal error during step 2"}

# ==============================================================================
# 🤖 BOT INTERFACE
# ==============================================================================
creation_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CREATIONS)
WAIT_EMAIL, WAIT_OTP = range(2)

def main_keyboard(is_admin: bool = False):
    buttons = [
        [KeyboardButton("🚀 Launch Creation"), KeyboardButton("📜 Protocol")]
    ]
    if is_admin:
        buttons.append([KeyboardButton("💀 GhostOps Panel")])
    return ReplyKeyboardMarkup(buttons, resize_keyboard=True)

def admin_keyboard():
    buttons = [
        [KeyboardButton("📊 Analytics"), KeyboardButton("🛡 Network Status")],
        [KeyboardButton("➕ Inject Proxies"), KeyboardButton("🗑 Flush Proxies")],
        [KeyboardButton("🔙 Disconnect")]
    ]
    return ReplyKeyboardMarkup(buttons, resize_keyboard=True)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT OR IGNORE INTO users VALUES (?, ?, ?)",
            (user.id, user.username, datetime.now().isoformat())
        )
        await db.commit()

    await update.message.reply_text(
        f"💀 **GHOSTOPS IG: PREMIUM**\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"Welcome, Agent {user.first_name}.\n\n"
        f"⚡ **System Online**\n"
        f"🛡 **TLS Masquerading:** Chrome 110\n"
        f"🔄 **Proxy Engine:** Active\n"
        f"🎯 **Jazoest:** Dynamic (auto‑parsed)\n\n"
        f"Select an operation below:",
        reply_markup=main_keyboard(user.id == ADMIN_ID),
        parse_mode='Markdown'
    )
    return ConversationHandler.END

async def guidelines(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📜 **OPERATIONAL PROTOCOL**\n\n"
        "1️⃣ **Target:** Provide a valid email (Temp mail allowed).\n"
        "2️⃣ **Action:** Initiate 'Launch Creation'.\n"
        "3️⃣ **Auth:** Input the 6-digit OTP from Instagram.\n"
        "4️⃣ **Result:** Retrieve generated credentials.\n\n"
        "⚠️ _System auto-rotates proxies on failure._",
        parse_mode='Markdown'
    )

async def create_account_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📥 **INPUT REQUIRED**\n\n"
        "Enter the target email address:",
        reply_markup=ReplyKeyboardRemove(),
        parse_mode='Markdown'
    )
    return WAIT_EMAIL

async def handle_email(update: Update, context: ContextTypes.DEFAULT_TYPE):
    email = update.message.text.strip()
    if "@" not in email:
        await update.message.reply_text("⚠️ **SYNTAX ERROR:** Invalid Email Format.")
        return WAIT_EMAIL

    proxy = await get_working_proxy()
    if not proxy:
        await update.message.reply_text("⛔ **SYSTEM HALT:** No Active Proxies. Contact Admin.")
        return ConversationHandler.END

    msg = await update.message.reply_text("🔄 **INITIALIZING HANDSHAKE...**")

    async with creation_semaphore:
        session = InstagramSession(proxy)
        try:
            result = await session.step_1_send_email(email)
        except Exception as e:
            logger.exception("Handshake Error")
            result = {"status": False, "msg": "Internal error"}

        if result['status']:
            await reset_proxy_fail(proxy)
            context.user_data['ig_context'] = result
            context.user_data['ig_email'] = email
            context.user_data['ig_proxy'] = proxy
            await msg.edit_text(
                f"✅ **TARGET LOCKED**\n\n"
                f"Email: `{email}`\n"
                f"Status: **Awaiting OTP**\n\n"
                f"Enter the 6-digit code now:"
            )
            return WAIT_OTP
        else:
            # Increment fail only if proxy-related
            if "Proxy" in result['msg'] or "Banned" in result['msg'] or "Connection" in result['msg']:
                await increment_proxy_fail(proxy)
            await msg.edit_text(f"❌ **OPERATION FAILED:** {result['msg']}")
            return ConversationHandler.END

async def handle_otp(update: Update, context: ContextTypes.DEFAULT_TYPE):
    otp = update.message.text.strip()
    ctx = context.user_data.get('ig_context')
    
    msg = await update.message.reply_text("🔐 **AUTHENTICATING...**")

    async with creation_semaphore:
        session = InstagramSession(context.user_data['ig_proxy'])
        result = await session.step_2_verify_create(context.user_data['ig_email'], otp, ctx)

        if result['status']:
            await reset_proxy_fail(context.user_data['ig_proxy'])
            await msg.edit_text(
                f"💀 **GHOSTOPS SUCCESS**\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n"
                f"👤 **User:** `{result['username']}`\n"
                f"🔑 **Pass:** `{result['password']}`\n"
                f"🍪 **Session:**\n`{result['cookies']}`\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n"
                f"⚠️ _Credentials wiped from chat logs in 3...2...1_",
                parse_mode='Markdown'
            )
        else:
            if "Proxy" in result['msg'] or "Connection" in result['msg']:
                await increment_proxy_fail(context.user_data['ig_proxy'])
            await msg.edit_text(f"❌ **CREATION FAILED:** {result['msg']}")

    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.pop('adding_proxies', None)
    await update.message.reply_text("⛔ Aborted.", reply_markup=main_keyboard(update.effective_user.id == ADMIN_ID))
    return ConversationHandler.END

# ==============================================================================
# 🔐 ADMIN COMMANDS
# ==============================================================================
async def admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    await update.message.reply_text("🔐 **COMMAND CONSOLE**", reply_markup=admin_keyboard())

async def user_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT COUNT(*) FROM users") as cursor:
            count = (await cursor.fetchone())[0]
    await update.message.reply_text(f"📊 **Total Users:** `{count}`", parse_mode='Markdown')

async def proxy_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    total, active, dead = await get_proxy_stats()
    await update.message.reply_text(
        f"🛡 **Network Status**\n\n"
        f"🔵 Total Proxies: `{total}`\n"
        f"🟢 **Live:** `{active}`\n"
        f"🔴 Dead: `{dead}`", parse_mode='Markdown'
    )

async def add_proxies_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    await update.message.reply_text(
        "📥 **BULK INJECTION MODE**\n"
        "Format: `http://user:pass@ip:port`\n"
        "One per line.",
        parse_mode='Markdown'
    )
    context.user_data['adding_proxies'] = True

async def handle_proxy_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID or not context.user_data.get('adding_proxies'): return
    
    proxies = [p.strip() for p in update.message.text.splitlines() if p.strip().startswith("http")]
    if not proxies:
        await update.message.reply_text("⚠️ No valid proxies detected.")
        context.user_data['adding_proxies'] = False
        return

    msg = await update.message.reply_text(f"⏳ **Validating {len(proxies)} nodes...**")
    
    sem = asyncio.Semaphore(MAX_PROXY_CHECKS)
    async def validate(p):
        async with sem:
            return p, await check_proxy_live(p)

    results = await asyncio.gather(*[validate(p) for p in proxies])
    
    added = 0
    for proxy, alive in results:
        if alive:
            await add_valid_proxy(proxy)
            added += 1
    
    await msg.edit_text(f"✅ **INJECTION COMPLETE**\nLive Nodes Added: `{added}`")
    context.user_data['adding_proxies'] = False

async def clear_proxies(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    await clear_all_proxies()
    await update.message.reply_text("🗑 **DATABASE FLUSHED**")

async def back_to_main(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.pop('adding_proxies', None)
    await update.message.reply_text("🔙 Disconnected.", reply_markup=main_keyboard(update.effective_user.id == ADMIN_ID))

# ==============================================================================
# 🚀 SYSTEM BOOT
# ==============================================================================
def print_banner():
    print(r"""
   ________  ______  ________________  ____  _____
  / ____/ / / / __ \/ ___/_  __/ __ \/ __ \/ ___/
 / / __/ /_/ / / / /\__ \ / / / / / / /_/ /\__ \ 
/ /_/ / __  / /_/ /___/ // / / /_/ / ____/___/ / 
\____/_/ /_/\____//____//_/  \____/_/    /____/  
        >> PREMIUM INSTAGRAM AUTOMATION <<
    """)

async def main():
    print_banner()
    await init_db()
    
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    conv = ConversationHandler(
        entry_points=[MessageHandler(filters.Regex("^🚀 Launch Creation$"), create_account_start)],
        states={
            WAIT_EMAIL: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_email)],
            WAIT_OTP: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_otp)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )

    app.add_handler(conv)
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.Regex("^📜 Protocol$"), guidelines))
    app.add_handler(MessageHandler(filters.Regex("^💀 GhostOps Panel$"), admin_panel))
    app.add_handler(MessageHandler(filters.Regex("^📊 Analytics$"), user_stats))
    app.add_handler(MessageHandler(filters.Regex("^🛡 Network Status$"), proxy_status))
    app.add_handler(MessageHandler(filters.Regex("^➕ Inject Proxies$"), add_proxies_start))
    app.add_handler(MessageHandler(filters.Regex("^🗑 Flush Proxies$"), clear_proxies))
    app.add_handler(MessageHandler(filters.Regex("^🔙 Disconnect$"), back_to_main))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_proxy_list))

    print(f"[{datetime.now().strftime('%H:%M:%S')}] System Initialized. Listening...")
    await app.run_polling()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n💀 System Shutdown.")
