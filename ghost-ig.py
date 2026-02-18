import os
import logging
import asyncio
import random
import string
import time
import base64
from datetime import datetime
from typing import Optional, Dict, Any, Tuple

import aiohttp
import aiosqlite
import rsa
from curl_cffi.requests import AsyncSession
from telegram import (
    Update, ReplyKeyboardMarkup, KeyboardButton, ReplyKeyboardRemove
)
from telegram.ext import (
    ApplicationBuilder, ContextTypes, CommandHandler,
    MessageHandler, filters, ConversationHandler
)

# ==============================================================================
# ⚙️ CONFIGURATION – EDIT THESE
# ==============================================================================
BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"          # Replace with your bot token
ADMIN_ID = 1234567890                       # Replace with your Telegram user ID
DB_FILE = "ghostops_prod.db"

# Proxy rotation settings
MAX_PROXY_FAILS = 3          # Mark proxy dead after this many failures
PROXY_CHECK_TIMEOUT = 10     # Seconds for proxy test
REQUEST_TIMEOUT = 30         # General request timeout

# Concurrency limits
MAX_CONCURRENT_CREATIONS = 5  # Max simultaneous account creations
MAX_PROXY_CHECKS = 10         # Max parallel proxy tests

# Logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ==============================================================================
# 📦 DATABASE (async with aiosqlite)
# ==============================================================================
async def init_db():
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute('''CREATE TABLE IF NOT EXISTS users 
                             (user_id INTEGER PRIMARY KEY, username TEXT, joined_date TEXT)''')
        await db.execute('''CREATE TABLE IF NOT EXISTS proxies 
                             (proxy_url TEXT PRIMARY KEY, status TEXT, fails INTEGER, last_checked TEXT)''')
        await db.commit()

async def add_valid_proxy(proxy_url: str):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT OR REPLACE INTO proxies VALUES (?, 'active', 0, ?)",
            (proxy_url, datetime.now().isoformat())
        )
        await db.commit()
    logger.info(f"✅ Proxy added: {proxy_url}")

async def clear_all_proxies():
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("DELETE FROM proxies")
        await db.commit()
    logger.info("🗑 All proxies cleared.")

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
    """Return the active proxy with the fewest failures."""
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT proxy_url FROM proxies WHERE status='active' ORDER BY fails ASC, RANDOM() LIMIT 1"
        ) as cursor:
            row = await cursor.fetchone()
    return row[0] if row else None

async def increment_proxy_fail(proxy_url: str):
    """Increment fail count; if fails >= MAX_PROXY_FAILS, mark as dead."""
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("UPDATE proxies SET fails = fails + 1 WHERE proxy_url=?", (proxy_url,))
        async with db.execute("SELECT fails FROM proxies WHERE proxy_url=?", (proxy_url,)) as cursor:
            fails = (await cursor.fetchone())[0]
        if fails >= MAX_PROXY_FAILS:
            await db.execute("UPDATE proxies SET status='dead' WHERE proxy_url=?", (proxy_url,))
            logger.warning(f"💀 Proxy marked dead after {fails} failures: {proxy_url}")
        await db.commit()

async def reset_proxy_fail(proxy_url: str):
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("UPDATE proxies SET fails=0 WHERE proxy_url=?", (proxy_url,))
        await db.commit()

# ==============================================================================
# 🌐 PROXY CHECKER (async)
# ==============================================================================
async def check_proxy_live(proxy_url: str) -> bool:
    """Test proxy by fetching Instagram's shared_data endpoint."""
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
                    if "config" in data:
                        return True
    except Exception as e:
        logger.debug(f"Proxy {proxy_url} failed: {e}")
    return False

# ==============================================================================
# 🔐 INSTAGRAM SESSION HANDLER (async, with dynamic token fetching)
# ==============================================================================
class InstagramSession:
    def __init__(self, proxy: Optional[str] = None):
        self.proxy = proxy
        self.session = AsyncSession(impersonate="chrome110")  # Async session
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
        self.session.headers.update({"User-Agent": self.user_agent})
        self.csrftoken = None
        self.mid = None
        self.public_key = None
        self.key_id = None

    async def fetch_initial_data(self):
        """Simulate a browser visit to obtain csrftoken, mid, and public key."""
        resp = await self.session.get("https://www.instagram.com/accounts/emailsignup/")
        self.csrftoken = self.session.cookies.get("csrftoken")
        self.mid = self.session.cookies.get("mid")
        if not self.csrftoken or not self.mid:
            raise Exception("Failed to obtain initial tokens")

        # Fetch public key
        key_resp = await self.session.get("https://www.instagram.com/api/v1/web/qe/sync/")
        if key_resp.status_code != 200:
            raise Exception("Failed to fetch public key")
        data = key_resp.json()
        self.key_id = data.get("key_id")
        self.public_key = data.get("public_key")
        if not self.key_id or not self.public_key:
            raise Exception("Public key missing in response")

        # Update headers with csrftoken for subsequent requests
        self.session.headers.update({"x-csrftoken": self.csrftoken})

    def encrypt_password(self, plain_password: str) -> str:
        """Encrypt password using Instagram's public RSA key."""
        pub_key = rsa.PublicKey.load_pkcs1_openssl_pem(self.public_key.encode())
        encrypted = rsa.encrypt(plain_password.encode(), pub_key)
        b64_enc = base64.b64encode(encrypted).decode()
        return f"#PWD_INSTAGRAM_BROWSER:0:{self.key_id}:{int(time.time())}:{b64_enc}"

    async def step_1_send_email(self, email: str) -> Dict[str, Any]:
        """Step 1: send email verification code."""
        try:
            await self.fetch_initial_data()

            raw_password = ''.join(random.choices(string.ascii_letters + string.digits + "#@!&", k=12))
            enc_password = self.encrypt_password(raw_password)

            data_dryrun = {
                'enc_password': enc_password,
                'email': email,
                'first_name': "IG Bot User",
                'username': '',
                'client_id': self.mid,
                'seamless_login_enabled': '1',
                'opt_into_one_tap': 'false',
                'jazoest': '21906',  # Note: This may become outdated; real bots fetch it dynamically
            }

            r1 = await self.session.post(
                'https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/',
                data=data_dryrun,
                timeout=REQUEST_TIMEOUT
            )

            if r1.status_code in [403, 429]:
                return {"status": False, "msg": "PROXY_BAN"}

            username = email.split('@')[0] + str(random.randint(100, 999))
            try:
                resp_json = r1.json()
                if "username_suggestions" in resp_json and resp_json["username_suggestions"]:
                    username = resp_json["username_suggestions"][0]
            except:
                pass

            data_dryrun['username'] = username
            await self.session.post('https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/', data=data_dryrun)

            await asyncio.sleep(random.uniform(1.5, 3.5))

            data_age = {'day': '15', 'month': '4', 'year': '2000', 'jazoest': '21906'}
            await self.session.post('https://www.instagram.com/api/v1/web/consent/check_age_eligibility/', data=data_age)

            await asyncio.sleep(random.uniform(1.5, 3.5))

            data_send = {'device_id': self.mid, 'email': email, 'jazoest': '21906'}
            r_email = await self.session.post('https://www.instagram.com/api/v1/accounts/send_verify_email/', data=data_send)

            if '"email_sent":true' in r_email.text:
                return {
                    "status": True,
                    "username": username,
                    "raw_password": raw_password,
                    "enc_password": enc_password,
                    "cookies": self.session.cookies.get_dict()
                }
            else:
                return {"status": False, "msg": "IG blocked email sending"}

        except Exception as e:
            logger.exception("Step 1 error")
            return {"status": False, "msg": str(e)}

    async def step_2_verify_create(self, email: str, otp: str, context_data: Dict[str, Any]) -> Dict[str, Any]:
        """Step 2: verify OTP and create account."""
        try:
            self.session.cookies.update(context_data['cookies'])

            await asyncio.sleep(random.uniform(1.5, 3.5))

            data_otp = {'code': otp, 'device_id': self.mid, 'email': email, 'jazoest': '21906'}
            r_otp = await self.session.post('https://www.instagram.com/api/v1/accounts/check_confirmation_code/', data=data_otp)

            signup_code = None
            if '"signup_code"' in r_otp.text:
                try:
                    signup_code = r_otp.json().get("signup_code")
                except:
                    return {"status": False, "msg": "Could not parse signup code"}
            else:
                return {"status": False, "msg": "Incorrect OTP or expired"}

            await asyncio.sleep(random.uniform(1.5, 3.5))

            data_final = {
                'enc_password': context_data['enc_password'],
                'day': '15', 'month': '4', 'year': '2000',
                'email': email,
                'first_name': "IG Bot User",
                'username': context_data['username'],
                'client_id': self.mid,
                'seamless_login_enabled': '1',
                'force_sign_up_code': signup_code,
                'jazoest': '21906'
            }
            r_create = await self.session.post('https://www.instagram.com/api/v1/web/accounts/web_create_ajax/', data=data_final)

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
                logger.error(f"Final creation failed: {r_create.text}")
                return {"status": False, "msg": "Instagram rejected final parameters"}

        except Exception as e:
            logger.exception("Step 2 error")
            return {"status": False, "msg": str(e)}

# ==============================================================================
# 🧵 CONCURRENCY CONTROL
# ==============================================================================
creation_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CREATIONS)

# ==============================================================================
# 🤖 TELEGRAM BOT HANDLERS
# ==============================================================================
WAIT_EMAIL, WAIT_OTP = range(2)

def main_keyboard(is_admin: bool = False):
    buttons = [
        [KeyboardButton("🚀 Create Account")],
        [KeyboardButton("📋 Guidelines")]
    ]
    if is_admin:
        buttons.append([KeyboardButton("🔐 Admin Panel")])
    return ReplyKeyboardMarkup(buttons, resize_keyboard=True)

def admin_keyboard():
    buttons = [
        [KeyboardButton("📊 User Stats"), KeyboardButton("🛡 Proxy Status")],
        [KeyboardButton("➕ Add Bulk Proxies"), KeyboardButton("🗑 Clear Proxies")],
        [KeyboardButton("🔙 Back to Main")]
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
        f"👻 **GhostOps IG (Production)**\n\n"
        f"Welcome {user.first_name}!\n"
        f"• Send **🚀 Create Account** to start.\n"
        f"• Read **📋 Guidelines** before using.\n"
        f"⚡ Auto‑Proxy Rotation | 🛡 Anti‑Ban",
        reply_markup=main_keyboard(user.id == ADMIN_ID),
        parse_mode='Markdown'
    )
    return ConversationHandler.END

async def guidelines(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📋 **How to use the bot**\n\n"
        "1️⃣ Use a valid email address (temporary emails may work).\n"
        "2️⃣ Click **🚀 Create Account** and send the email.\n"
        "3️⃣ Wait for the 6‑digit Instagram code.\n"
        "4️⃣ Send the code back here.\n"
        "5️⃣ Receive your new Instagram username, password, and cookies.\n\n"
        "⚠️ If you get an error, try again with a different email or proxy.\n"
        "📢 No forced joins – you're free to use the bot immediately!",
        parse_mode='Markdown'
    )
    return

async def create_account_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📧 **Send the Email Address** to use:\n"
        "(e.g., `example@gmail.com`)",
        reply_markup=ReplyKeyboardRemove(),
        parse_mode='Markdown'
    )
    return WAIT_EMAIL

async def handle_email(update: Update, context: ContextTypes.DEFAULT_TYPE):
    email = update.message.text.strip()
    if "@" not in email:
        await update.message.reply_text("⚠️ Invalid Email. Please try again.")
        return WAIT_EMAIL

    proxy = await get_working_proxy()
    if not proxy:
        await update.message.reply_text("❌ **Error:** No Active Proxies in DB. Contact Admin.")
        return ConversationHandler.END

    msg = await update.message.reply_text("⏳ **Connecting to Instagram...**")

    async with creation_semaphore:
        session = InstagramSession(proxy)
        try:
            result = await session.step_1_send_email(email)
        except Exception as e:
            logger.exception("Step 1 unexpected error")
            result = {"status": False, "msg": str(e)}

        if result['status']:
            await reset_proxy_fail(proxy)
            context.user_data['ig_context'] = result
            context.user_data['ig_email'] = email
            context.user_data['ig_proxy'] = proxy
            await msg.edit_text(
                f"✅ **Email Sent!**\n"
                f"Check `{email}` and send me the **6‑digit code**."
            )
            return WAIT_OTP
        else:
            if result['msg'] == "PROXY_BAN" or "ProxyError" in result['msg']:
                await increment_proxy_fail(proxy)
            await msg.edit_text(f"❌ **Failed:** {result['msg']}")
            return ConversationHandler.END

async def handle_otp(update: Update, context: ContextTypes.DEFAULT_TYPE):
    otp = update.message.text.strip()
    ctx = context.user_data.get('ig_context')
    email = context.user_data.get('ig_email')
    proxy = context.user_data.get('ig_proxy')

    if not ctx or not email or not proxy:
        await update.message.reply_text("❌ Session expired. Please start again.")
        return ConversationHandler.END

    msg = await update.message.reply_text("⏳ **Verifying Code...**")

    async with creation_semaphore:
        session = InstagramSession(proxy)
        result = await session.step_2_verify_create(email, otp, ctx)

        if result['status']:
            await reset_proxy_fail(proxy)
            await msg.edit_text(
                f"🎉 **Account Created Successfully!**\n\n"
                f"👤 **Username:** `{result['username']}`\n"
                f"🔑 **Password:** `{result['password']}`\n"
                f"🍪 **Cookies:**\n`{result['cookies']}`\n\n"
                f"📌 Save this information – it won't be shown again.",
                parse_mode='Markdown'
            )
        else:
            if "ProxyError" in result['msg']:
                await increment_proxy_fail(proxy)
            await msg.edit_text(f"❌ **Failed:** {result['msg']}")

    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Cancelled.", reply_markup=main_keyboard(update.effective_user.id == ADMIN_ID))
    return ConversationHandler.END

# Admin handlers
async def admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if user.id != ADMIN_ID:
        await update.message.reply_text("⛔ Access Denied")
        return
    await update.message.reply_text("🔐 **Admin Menu**", reply_markup=admin_keyboard())

async def user_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT COUNT(*) FROM users") as cursor:
            count = (await cursor.fetchone())[0]
    await update.message.reply_text(f"📊 **Total Users:** `{count}`", parse_mode='Markdown')

async def proxy_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    total, active, dead = await get_proxy_stats()
    await update.message.reply_text(
        f"🛡 **Proxy Health**\n\n"
        f"🔵 Total: `{total}`\n"
        f"🟢 **Live:** `{active}`\n"
        f"🔴 Dead: `{dead}`", parse_mode='Markdown'
    )

async def add_proxies_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    await update.message.reply_text(
        "📥 **Bulk Proxy Mode**\n"
        "Send one proxy per line:\n"
        "`http://user:pass@ip:port` or `https://...`\n"
        "Duplicates will be ignored.",
        parse_mode='Markdown'
    )
    context.user_data['adding_proxies'] = True

async def handle_proxy_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Only process if user is admin and in adding mode
    if update.effective_user.id != ADMIN_ID or not context.user_data.get('adding_proxies'):
        return
    text = update.message.text
    raw_list = text.splitlines()
    unique_proxies = set(p.strip() for p in raw_list if p.strip().startswith(("http://", "https://")))
    if not unique_proxies:
        await update.message.reply_text("No valid proxies found.")
        context.user_data['adding_proxies'] = False
        return

    await update.message.reply_text(f"⏳ **Testing {len(unique_proxies)} unique proxies...**")

    sem = asyncio.Semaphore(MAX_PROXY_CHECKS)
    async def test_proxy(proxy):
        async with sem:
            alive = await check_proxy_live(proxy)
            return proxy, alive

    tasks = [test_proxy(proxy) for proxy in unique_proxies]
    results = await asyncio.gather(*tasks)

    added = 0
    for proxy, alive in results:
        if alive:
            await add_valid_proxy(proxy)
            added += 1

    dead = len(unique_proxies) - added
    await update.message.reply_text(f"✅ **Result:** Added `{added}` | Dead `{dead}`", parse_mode='Markdown')
    context.user_data['adding_proxies'] = False

async def clear_proxies(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    await clear_all_proxies()
    await update.message.reply_text("🗑 **All proxies deleted.** Database is clean.")

async def back_to_main(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    await update.message.reply_text("🔙 Main Menu", reply_markup=main_keyboard(user.id == ADMIN_ID))
    # Clear any admin mode
    context.user_data['adding_proxies'] = False
    return ConversationHandler.END

# ==============================================================================
# 🚀 MAIN
# ==============================================================================
async def main():
    await init_db()

    app = ApplicationBuilder().token(BOT_TOKEN).build()

    # Conversation for account creation
    conv_handler = ConversationHandler(
        entry_points=[MessageHandler(filters.Regex("^🚀 Create Account$"), create_account_start)],
        states={
            WAIT_EMAIL: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_email)],
            WAIT_OTP: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_otp)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )
    app.add_handler(conv_handler)

    # Other handlers
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.Regex("^📋 Guidelines$"), guidelines))
    app.add_handler(MessageHandler(filters.Regex("^🔐 Admin Panel$"), admin_panel))
    app.add_handler(MessageHandler(filters.Regex("^📊 User Stats$"), user_stats))
    app.add_handler(MessageHandler(filters.Regex("^🛡 Proxy Status$"), proxy_status))
    app.add_handler(MessageHandler(filters.Regex("^➕ Add Bulk Proxies$"), add_proxies_start))
    app.add_handler(MessageHandler(filters.Regex("^🗑 Clear Proxies$"), clear_proxies))
    app.add_handler(MessageHandler(filters.Regex("^🔙 Back to Main$"), back_to_main))

    # Proxy list input – must be after admin checks, so we use a separate handler
    # It will only trigger when user_data['adding_proxies'] is True (ensured in handle_proxy_list)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_proxy_list))

    print("👻 GhostOps IG (Production) Started...")
    await app.run_polling()

if __name__ == '__main__':
    asyncio.run(main())
