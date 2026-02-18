import os
import logging
import asyncio
import sqlite3
import random
import time
import string
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from telegram import (
    Update, ReplyKeyboardMarkup, KeyboardButton, ReplyKeyboardRemove
)
from telegram.ext import (
    ApplicationBuilder, ContextTypes, CommandHandler,
    MessageHandler, filters
)

# ==============================================================================
# ⚙️ CONFIGURATION – EDIT THESE
# ==============================================================================
BOT_TOKEN = "8576058726:AAEbtWq82hw8AwpwXb9E2u0xv07rh3sKZ48"
ADMIN_ID = 8469803348
DB_FILE = "ghostops_ig.db"

MAX_WORKERS = 15
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

# Logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ================= DATABASE (fixed stats) =================
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users 
                     (user_id INTEGER PRIMARY KEY, username TEXT, joined_date TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS proxies 
                     (proxy_url TEXT PRIMARY KEY, status TEXT, fails INTEGER, last_checked TEXT)''')
        conn.commit()

def add_valid_proxy(proxy_url):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO proxies VALUES (?, 'active', 0, ?)", 
                  (proxy_url, datetime.now().isoformat()))
        conn.commit()

def clear_all_proxies():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM proxies")
        conn.commit()

def get_proxy_stats():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM proxies")
        total = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM proxies WHERE status='active'")
        active = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM proxies WHERE status='dead'")
        dead = c.fetchone()[0]
    return total, active, dead

def get_working_proxy():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT proxy_url FROM proxies WHERE status='active' ORDER BY RANDOM() LIMIT 1")
        res = c.fetchone()
    return res[0] if res else None

def report_dead_proxy(proxy_url):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("UPDATE proxies SET status='dead', fails=fails+1 WHERE proxy_url=?", (proxy_url,))
        conn.commit()
    logger.warning(f"💀 Proxy Died: {proxy_url}")

# ================= SIMPLE PROXY CHECKER (original) =================
def check_proxy_live(proxy_url):
    proxies = {"http": proxy_url, "https": proxy_url}
    try:
        r = requests.get("https://www.instagram.com", proxies=proxies, timeout=10)
        return r.status_code == 200
    except:
        return False

# ================= IG LOGIC (original, unchanged) =================
def generate_password():
    chars = string.ascii_letters + string.digits + "#@!&"
    return ''.join(random.choice(chars) for _ in range(12))

class InstagramCreator:
    def __init__(self, proxy):
        self.session = requests.Session()
        self.proxy = proxy
        
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded',
            'x-csrftoken': 'nu94r8FbL9bCmhtUkJuCPK',
            'x-ig-app-id': '936619743392459',
            'origin': 'https://www.instagram.com',
            'referer': 'https://www.instagram.com/accounts/emailsignup/',
            'accept-language': 'en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7'
        }
        
        self.cookies = {
            'csrftoken': 'nu94r8FbL9bCmhtUkJuCPK',
            'mid': 'aQLm1gABAAE842f-IkSwe_vjC30a',
            'ig_nrcb': '1',
            'datr': '1eYCaXxZangEyVhuLFgYLFCM',
        }
        
        self.session.headers.update(self.headers)
        self.session.cookies.update(self.cookies)
        
        if self.proxy:
            self.session.proxies.update({'http': self.proxy, 'https': self.proxy})

    def _sleep(self):
        time.sleep(random.uniform(1.5, 3.5))

    def step_1_send_email(self, email):
        password = generate_password()
        enc_password = f'#PWD_INSTAGRAM_BROWSER:0:{int(time.time())}:{password}'
        
        try:
            self._sleep()
            data_dryrun = {
                'enc_password': enc_password,
                'email': email,
                'first_name': "IG Bot User",
                'username': '',
                'client_id': self.cookies.get('mid'),
                'seamless_login_enabled': '1',
                'opt_into_one_tap': 'false',
                'jazoest': '21906',
            }

            r1 = self.session.post(
                'https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/',
                data=data_dryrun
            )
            
            if r1.status_code in [403, 429]:
                return {"status": False, "msg": "PROXY_BAN"}

            username = email.split('@')[0] + str(random.randint(100, 999))
            try:
                resp_json = r1.json()
                if "username_suggestions" in resp_json and len(resp_json["username_suggestions"]) > 0:
                    username = resp_json["username_suggestions"][0]
            except:
                pass
            
            data_dryrun['username'] = username
            self.session.post('https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/', data=data_dryrun)

            self._sleep()
            data_age = {'day': '15', 'month': '4', 'year': '2000', 'jazoest': '21906'}
            self.session.post('https://www.instagram.com/api/v1/web/consent/check_age_eligibility/', data=data_age)

            self._sleep()
            data_send = {'device_id': self.cookies.get('mid'), 'email': email, 'jazoest': '21906'}
            r_email = self.session.post('https://www.instagram.com/api/v1/accounts/send_verify_email/', data=data_send)
            
            if '"email_sent":true' in r_email.text:
                return {
                    "status": True, 
                    "username": username, 
                    "password": password, 
                    "enc_pass": enc_password,
                    "cookies": self.session.cookies.get_dict() 
                }
            else:
                return {"status": False, "msg": "IG Blocked Request (Try switching IP/Proxy)."}

        except Exception as e:
            return {"status": False, "msg": str(e)}

    def step_2_verify_create(self, email, otp, context_data):
        try:
            self.session.cookies.update(context_data['cookies'])
            self._sleep()
            
            data_otp = {'code': otp, 'device_id': self.cookies.get('mid'), 'email': email, 'jazoest': '21906'}
            r_otp = self.session.post('https://www.instagram.com/api/v1/accounts/check_confirmation_code/', data=data_otp)
            
            signup_code = ""
            if '"signup_code"' in r_otp.text:
                try:
                    signup_code = r_otp.json().get("signup_code")
                except:
                    return {"status": False, "msg": "OTP Error: Could not parse signup code."}
            else:
                return {"status": False, "msg": "Incorrect OTP or OTP Expired."}

            self._sleep()
            data_final = {
                'enc_password': context_data['enc_pass'],
                'day': '15', 'month': '4', 'year': '2000',
                'email': email,
                'first_name': "IG Bot User",
                'username': context_data['username'],
                'client_id': self.cookies.get('mid'),
                'seamless_login_enabled': '1',
                'force_sign_up_code': signup_code,
                'jazoest': '21906'
            }
            
            r_create = self.session.post('https://www.instagram.com/api/v1/web/accounts/web_create_ajax/', data=data_final)

            if '"account_created":true' in r_create.text:
                final_cookies = self.session.cookies.get_dict()
                cookie_str = "; ".join([f"{k}={v}" for k, v in final_cookies.items()])
                return {"status": True, "cookies": cookie_str, "username": context_data['username'], "password": context_data['password']}
            else:
                return {"status": False, "msg": "Final Creation Failed (IG rejected parameters)."}

        except Exception as e:
            return {"status": False, "msg": str(e)}

# ================= KEYBOARDS =================
def main_keyboard(is_admin=False):
    buttons = [
        [KeyboardButton("🚀 Create Account")],
        [KeyboardButton("📋 Guidelines")]          # Replaced Support
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

# ================= HANDLERS =================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    with sqlite3.connect(DB_FILE) as conn:
        conn.cursor().execute("INSERT OR IGNORE INTO users VALUES (?, ?, ?)", 
                  (user.id, user.username, datetime.now().isoformat()))
        conn.commit()
    
    await update.message.reply_text(
        f"👻 **GhostOps IG v2.0 (No Force Join)**\n\n"
        f"Welcome {user.first_name}!\n"
        f"• Send **🚀 Create Account** to start.\n"
        f"• Read **📋 Guidelines** before using.\n"
        f"⚡ Auto‑Proxy Rotation | 🛡 Anti‑Ban",
        reply_markup=main_keyboard(user.id == ADMIN_ID), 
        parse_mode='Markdown'
    )
    context.user_data['mode'] = None

async def handle_buttons(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    user = update.effective_user

    if text == "📋 Guidelines":
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

    if text == "🚀 Create Account":
        # No force join check – everyone can use
        await update.message.reply_text(
            "📧 **Send the Email Address** to use:\n"
            "(e.g., `example@gmail.com`)",
            reply_markup=ReplyKeyboardRemove(),
            parse_mode='Markdown'
        )
        context.user_data['mode'] = 'wait_email'
        return

    if text == "🔐 Admin Panel":
        if user.id == ADMIN_ID:
            await update.message.reply_text("🔐 **Admin Menu**", reply_markup=admin_keyboard())
        else:
            await update.message.reply_text("⛔ Access Denied")
        return

    if text == "🔙 Back to Main":
        context.user_data['mode'] = None
        await update.message.reply_text("🔙 Main Menu", reply_markup=main_keyboard(user.id == ADMIN_ID))
        return

    # Admin features
    if user.id == ADMIN_ID:
        if text == "📊 User Stats":
            with sqlite3.connect(DB_FILE) as conn:
                count = conn.cursor().execute("SELECT COUNT(*) FROM users").fetchone()[0]
            await update.message.reply_text(f"📊 **Total Users:** `{count}`", parse_mode='Markdown')
            
        elif text == "🛡 Proxy Status":
            total, active, dead = get_proxy_stats()
            await update.message.reply_text(
                f"🛡 **Proxy Health**\n\n"
                f"🔵 Total: `{total}`\n"
                f"🟢 **Live:** `{active}`\n"
                f"🔴 Dead: `{dead}`", parse_mode='Markdown')
            
        elif text == "➕ Add Bulk Proxies":
            await update.message.reply_text(
                "📥 **Bulk Proxy Mode**\n"
                "Send one proxy per line:\n"
                "`http://user:pass@ip:port`\n"
                "Duplicates will be ignored.",
                parse_mode='Markdown')
            context.user_data['mode'] = 'add_proxies'
            
        elif text == "🗑 Clear Proxies":
            clear_all_proxies()
            await update.message.reply_text("🗑 **All proxies deleted.** Database is clean.")

async def handle_text_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not update.message or not update.message.text: return
    text = update.message.text
    mode = context.user_data.get('mode')

    # Bulk proxy adder (admin only)
    if mode == 'add_proxies' and user.id == ADMIN_ID:
        raw_list = text.splitlines()
        unique_proxies = set(p.strip() for p in raw_list if p.strip().startswith(("http://", "https://")))
        if len(unique_proxies) < len(raw_list):
            await update.message.reply_text(f"⚠️ Removed {len(raw_list)-len(unique_proxies)} duplicate(s).")
        
        await update.message.reply_text(f"⏳ **Testing {len(unique_proxies)} unique proxies...**")
        
        added = 0
        failed = 0
        loop = asyncio.get_running_loop()
        
        for proxy in unique_proxies:
            is_alive = await loop.run_in_executor(executor, check_proxy_live, proxy)
            if is_alive:
                add_valid_proxy(proxy)
                added += 1
            else:
                failed += 1
                
        await update.message.reply_text(f"✅ **Result:** Added `{added}` | Dead `{failed}`", parse_mode='Markdown')
        context.user_data['mode'] = None
        return

    # Email step
    if mode == 'wait_email':
        email = text.strip()
        if "@" not in email:
            await update.message.reply_text("⚠️ Invalid Email. Please try again.")
            return

        msg = await update.message.reply_text("⏳ **Connecting to Instagram...**")
        
        proxy = get_working_proxy()
        if not proxy:
            await msg.edit_text("❌ **Error:** No Active Proxies in DB. Contact Admin.")
            return

        loop = asyncio.get_running_loop()
        creator = InstagramCreator(proxy)
        result = await loop.run_in_executor(executor, creator.step_1_send_email, email)

        if result['status']:
            context.user_data['ig_context'] = result
            context.user_data['ig_email'] = email
            context.user_data['ig_proxy'] = proxy
            context.user_data['mode'] = 'wait_otp'
            
            await msg.edit_text(
                f"✅ **Email Sent!**\n"
                f"Check `{email}` and send me the **6‑digit code**."
            )
        else:
            if result['msg'] == "PROXY_BAN":
                report_dead_proxy(proxy)
            await msg.edit_text(f"❌ **Failed:** {result['msg']}")
            context.user_data['mode'] = None
            await update.message.reply_text("🔙 Returning to menu...", reply_markup=main_keyboard(user.id == ADMIN_ID))
        return

    # OTP step
    if mode == 'wait_otp':
        otp = text.strip()
        msg = await update.message.reply_text("⏳ **Verifying Code...**")
        
        ctx = context.user_data.get('ig_context')
        email = context.user_data.get('ig_email')
        proxy = context.user_data.get('ig_proxy')

        if not ctx:
            await msg.edit_text("❌ Session expired. Please start again.")
            return

        loop = asyncio.get_running_loop()
        creator = InstagramCreator(proxy)
        result = await loop.run_in_executor(executor, creator.step_2_verify_create, email, otp, ctx)

        if result['status']:
            await msg.edit_text(
                f"🎉 **Account Created Successfully!**\n\n"
                f"👤 **Username:** `{result['username']}`\n"
                f"🔑 **Password:** `{result['password']}`\n"
                f"🍪 **Cookies:**\n`{result['cookies']}`\n\n"
                f"📌 Save this information – it won't be shown again.",
                parse_mode='Markdown'
            )
        else:
            if result['msg'].startswith("PROXY_ERROR"):
                report_dead_proxy(proxy)
            await msg.edit_text(f"❌ **Failed:** {result['msg']}")
        
        context.user_data['mode'] = None
        await update.message.reply_text("✅ Done.", reply_markup=main_keyboard(user.id == ADMIN_ID))
        return

if __name__ == '__main__':
    if not os.path.exists('logs'): os.makedirs('logs')
    init_db()
    print("👻 GhostOps IG Bot v2.0 (No Force Join) Started...")
    
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.Regex("^(🚀|📋|🔐|📊|🛡|➕|🗑|🔙)"), handle_buttons))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_input))
    
    app.run_polling()
