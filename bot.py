import os
import json
import time
import random
import string
import requests
import telebot
from telebot import types
from urllib.parse import urlparse, parse_qs, unquote

# --- Configuration ---
BOT_TOKEN = 'YOUR_BOT_TOKEN_HERE'  # Replace with your actual token
ADMIN_CHAT_ID = ''  # Replace with admin ID if needed
CHANNEL_IDS = ['@YourChannel']  # Replace with your channel usernames

# Initialize Bot
bot = telebot.TeleBot(BOT_TOKEN, parse_mode='HTML')

# --- Helper Functions ---

def rand_ip():
    return f"{random.randint(100, 200)}.{random.randint(10, 250)}.{random.randint(10, 250)}.{random.randint(1, 250)}"

def rand_name():
    names = ['Aarav', 'Vihaan', 'Reyansh', 'Ayaan', 'Arjun', 'Kabir', 'Advait', 'Vivaan', 'Aadhya', 'Anaya', 'Diya', 'Myra', 'Kiara', 'Isha', 'Meera', 'Pari', 'Saanvi', 'Navya', 'Riya', 'Anika']
    return f"{random.choice(names)}{random.randint(100, 999)}"

def rand_phone():
    return f"9{random.randint(100000000, 999999999)}"

def rand_gender():
    return "MALE" if random.choice([True, False]) else "FEMALE"

def rand_hex(length=16):
    return ''.join(random.choices(string.hexdigits.lower(), k=length))

# --- Data Management ---

DATA_DIR = "data"
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

def get_user_file_path(chat_id, suffix):
    return os.path.join(DATA_DIR, f"{chat_id}_{suffix}.json")

def get_or_create_user_data(chat_id):
    path = get_user_file_path(chat_id, "shein")
    if os.path.exists(path):
        with open(path, 'r') as f:
            try:
                data = json.load(f)
                # Ensure defaults
                data.setdefault('shein_accounts', {})
                data.setdefault('coupon_count', 0)
                data.setdefault('cookie_workflow_active', False)
                return data
            except json.JSONDecodeError:
                pass
    
    return {
        'chat_id': chat_id,
        'step': 'start',
        'shein_accounts': {},
        'coupon_count': 0,
        'cookie_workflow_active': False,
        'created_at': time.strftime('%Y-%m-%d %H:%M:%S')
    }

def save_user_data(chat_id, data):
    with open(get_user_file_path(chat_id, "shein"), 'w') as f:
        json.dump(data, f, indent=4)

def save_instagram_data(chat_id, data):
    with open(get_user_file_path(chat_id, "insta"), 'w') as f:
        json.dump(data, f, indent=4)

# --- HTTP Request Wrapper ---

def http_call(url, data=None, headers=None, method="GET", return_headers=False, proxy=None):
    if headers is None:
        headers = {}
    
    # Convert list headers to dict if necessary (common in PHP conversions)
    header_dict = {}
    if isinstance(headers, list):
        for h in headers:
            if ':' in h:
                k, v = h.split(':', 1)
                header_dict[k.strip()] = v.strip()
    else:
        header_dict = headers

    # Default Headers for Anti-Bot
    if 'User-Agent' not in header_dict:
        header_dict['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
    if 'X-Forwarded-For' not in header_dict:
        header_dict['X-Forwarded-For'] = rand_ip()

    session = requests.Session()
    
    # Advanced connection settings are handled by requests automatically, 
    # but we can set specific adapters if needed for specific TLS versions.
    # For simplicity in Python, we trust requests default SSL context.
    
    try:
        req_kwargs = {
            "headers": header_dict,
            "timeout": 30,
            "allow_redirects": True,
            "verify": False # Mimics CURLOPT_SSL_VERIFYPEER = false
        }

        if proxy:
             req_kwargs["proxies"] = {"http": proxy, "https": proxy}

        if method.upper() == "POST":
            if isinstance(data, (dict, list)):
                 # If content-type is json, dump it, else let requests handle form-url-encoded
                if 'application/json' in header_dict.get('Content-Type', '').lower():
                    req_kwargs["data"] = json.dumps(data) if isinstance(data, (dict, list)) else data
                else:
                    req_kwargs["data"] = data
            else:
                req_kwargs["data"] = data
            response = session.post(url, **req_kwargs)
        else:
            if data:
                req_kwargs["params"] = data
            response = session.get(url, **req_kwargs)

        if return_headers:
             # Mimic PHP header + body separation
             # In Python requests, we just return the object or specific parts
             return {'success': True, 'headers': dict(response.headers), 'body': response.text, 'http_code': response.status_code}
        
        return {'success': True, 'body': response.text, 'http_code': response.status_code}

    except Exception as e:
        print(f"Request Error: {e}")
        return {'success': False, 'error': str(e), 'http_code': 0, 'body': ''}

# --- Core Logic ---

def validate_instagram_cookie(cookie_string):
    required = ['sessionid', 'csrftoken', 'ds_user_id']
    found = {}
    
    parts = cookie_string.split(';')
    for part in parts:
        part = part.strip()
        if '=' in part:
            k, v = part.split('=', 1)
            k = k.strip()
            if k in required:
                found[k] = v.strip()
    
    for req in required:
        if req not in found or not found[req]:
            return {'valid': False, 'missing': req}
            
    return {'valid': True, 'cookies': found}

def auto_generate_shein_account(chat_id):
    user_data = get_or_create_user_data(chat_id)
    bot.send_message(chat_id, "🔄 Generating new Shein account automatically (no OTP needed)...")

    # 1. Get Client Token
    client_token = None
    for _ in range(5):
        ip = rand_ip()
        ad_id = rand_hex(16)
        url = "https://api.sheinindia.in/uaas/jwt/token/client"
        headers = [
            "Client_type: Android/29", "Accept: application/json", "Client_version: 1.0.8",
            "User-Agent: Android", "X-Tenant-Id: SHEIN", f"Ad_id: {ad_id}",
            "X-Tenant: B2C", "Content-Type: application/x-www-form-urlencoded",
            f"X-Forwarded-For: {ip}"
        ]
        res = http_call(url, "grantType=client_credentials&clientName=trusted_client&clientSecret=secret", headers, "POST")
        try:
            j = json.loads(res['body'])
            if 'access_token' in j:
                client_token = j['access_token']
                break
        except: pass
    
    if not client_token:
        bot.send_message(chat_id, "❌ Failed to get client token.")
        return

    # 2. Find Unregistered Number
    mobile = None
    for _ in range(50):
        candidate = rand_phone()
        ip = rand_ip()
        ad_id = rand_hex(16)
        url = "https://api.sheinindia.in/uaas/accountCheck?client_type=Android%2F29&client_version=1.0.8"
        headers = [
            f"Authorization: Bearer {client_token}", "Requestid: account_check", "X-Tenant: B2C",
            "Accept: application/json", "User-Agent: Android", "Client_type: Android/29",
            "Client_version: 1.0.8", "X-Tenant-Id: SHEIN", f"Ad_id: {ad_id}",
            "Content-Type: application/x-www-form-urlencoded", f"X-Forwarded-For: {ip}"
        ]
        res = http_call(url, f"mobileNumber={candidate}", headers, "POST")
        try:
            j = json.loads(res['body'])
            if j.get('success') is False:
                mobile = candidate
                break
        except: pass

    if not mobile:
        bot.send_message(chat_id, "❌ Could not find unregistered number. Try again later.")
        return

    # 3. Generate Creator Token
    name = rand_name()
    gender = rand_gender()
    user_id_shein = rand_hex(16)
    
    payload = {
        "client_type": "Android/29",
        "client_version": "1.0.8",
        "gender": gender,
        "phone_number": mobile,
        "secret_key": "3LFcKwBTXcsMzO5LaUbNYoyMSpt7M3RP5dW9ifWffzg",
        "user_id": user_id_shein,
        "user_name": name
    }
    
    ip = rand_ip()
    ad_id = rand_hex(16)
    headers = [
        "Accept: application/json", "User-Agent: Android", "Client_type: Android/29",
        "Client_version: 1.0.8", "X-Tenant-Id: SHEIN", f"Ad_id: {ad_id}",
        "Content-Type: application/json; charset=UTF-8", f"X-Forwarded-For: {ip}"
    ]
    
    res = http_call("https://shein-creator-backend-151437891745.asia-south1.run.app/api/v1/auth/generate-token", payload, headers, "POST")
    
    creator_token = None
    try:
        j = json.loads(res['body'])
        creator_token = j.get('access_token')
    except: pass

    if not creator_token:
        bot.send_message(chat_id, "❌ Failed to generate creator token.")
        return

    # Save
    user_data['shein_accounts'][mobile] = {
        'mobile_number': mobile,
        'creator_token': creator_token,
        'profile_data': {'firstName': name, 'mobileNumber': mobile, 'genderType': gender},
        'instagram': {},
        'created_at': time.strftime('%Y-%m-%d %H:%M:%S')
    }
    save_user_data(chat_id, user_data)
    
    bot.send_message(chat_id, f"✅ New Shein account generated!\n\n📱 Mobile: +91-{mobile}\n👤 Name: {name}\n🔑 Ready for Instagram linking")
    send_shein_account_menu(chat_id, user_data, "✅ Account created successfully!\n\n")

def get_instagram_oauth(cookie_string, creator_token, ad_id, ip, mode='connect'):
    user_agent = 'Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36'
    
    # Simple parsing if pipe-separated
    if '|' in cookie_string:
        parts = cookie_string.split('|')
        cookie_string = parts[-1].strip()
    
    cookie_string = cookie_string.replace("cookie:", "").strip()
    
    # Validation
    validity = validate_instagram_cookie(cookie_string)
    if not validity['valid']:
        return {'success': False, 'error': f"Invalid cookie: missing {validity.get('missing')}"}

    # Clean and Append required
    cookie_string = cookie_string.strip()
    cookie_string += "; ig_nrcb=1; ps_l=1; ps_n=1"
    
    url = "https://www.instagram.com/consent/?flow=ig_biz_login_oauth&params_json=%7B%22client_id%22%3A%22713904474873404%22%2C%22redirect_uri%22%3A%22https%3A%5C%2F%5C%2Fsheinverse.galleri5.com%5C%2Finstagram%22%2C%22response_type%22%3A%22code%22%2C%22state%22%3A%22your_csrf_token%22%2C%22scope%22%3A%22instagram_business_basic%22%2C%22logger_id%22%3A%22732d54ea-9582-49f0-8dfb-48c5015047ea%22%2C%22app_id%22%3A%22713904474873404%22%2C%22platform_app_id%22%3A%22713904474873404%22%7D&source=oauth_permissions_page_www"
    
    headers = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "cookie": cookie_string,
        "user-agent": user_agent,
        "sec-fetch-site": "none",
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1"
    }
    
    # First Request to get Tokens
    res = http_call(url, None, headers, "GET", True)
    if not res['success']: return res
    
    body = res['body']
    
    # Extraction regexes
    import re
    av = re.search(r'"actorID"\s*:\s*"(\d+)"', body)
    rev = re.search(r'"rev"\s*:\s*(\d+)', body)
    hs = re.search(r'"haste_session"\s*:\s*"([^"]+)"', body)
    hsi = re.search(r'"hsi"\s*:\s*"([^"]+)"', body)
    fb_dtsg = re.search(r'"f"\s*:\s*"([^"]+)"', body)
    jazoest = re.search(r'jazoest=(\d+)', body)
    lsd = re.search(r'"LSD",\[,\{"token":"([^"]+)"\}', body)
    spin_r = re.search(r'"__spin_r"\s*:\s*(\d+)', body)
    spin_t = re.search(r'"__spin_t"\s*:\s*(\d+)', body)
    experience_id = re.search(r'"experience_id"\s*:\s*"([^"]+)"', body)
    
    if not (fb_dtsg and lsd and experience_id):
        return {'success': False, 'error': 'Failed to extract tokens (cookie may be expired)'}
    
    # Extract CSRF from cookie string for headers
    csrftoken = ""
    for p in cookie_string.split(';'):
        if p.strip().startswith("csrftoken="):
            csrftoken = p.strip()[10:]
            break

    # Construct GraphQL Mutation
    variables = json.dumps({
        "input": {
            "client_mutation_id": "2",
            "actor_id": av.group(1) if av else "",
            "device_id": None,
            "experience_id": experience_id.group(1) if experience_id else "",
            "extra_params_json": json.dumps({
                "client_id": "713904474873404",
                "redirect_uri": "https://sheinverse.galleri5.com/instagram",
                "response_type": "code",
                "state": None,
                "scope": "instagram_business_basic",
                "logger_id": rand_hex(18),
                "app_id": "713904474873404",
                "platform_app_id": "713904474873404"
            }),
            "flow": "IG_BIZ_LOGIN_OAUTH",
            "inputs_json": json.dumps({"instagram_business_basic": "true"}),
            "outcome": "APPROVED",
            "outcome_data_json": "{}",
            "prompt": "IG_BIZ_LOGIN_OAUTH_PERMISSION_CARD",
            "runtime": "SAHARA",
            "source": "oauth_permissions_page_www",
            "surface": "INSTAGRAM_WEB"
        }
    })

    post_data = {
        'av': av.group(1) if av else "",
        '__user': '0',
        '__a': '1',
        '__req': '6',
        '__hs': hs.group(1) if hs else "",
        'dpr': '2',
        '__ccg': 'EXCELLENT',
        '__rev': rev.group(1) if rev else "",
        '__hsi': hsi.group(1) if hsi else "",
        '__comet_req': '15',
        'fb_dtsg': fb_dtsg.group(1) if fb_dtsg else "",
        'jazoest': jazoest.group(1) if jazoest else "",
        'lsd': lsd.group(1) if lsd else "",
        '__spin_r': spin_r.group(1) if spin_r else "",
        '__spin_b': 'trunk',
        '__spin_t': spin_t.group(1) if spin_t else "",
        'fb_api_caller_class': 'RelayModern',
        'fb_api_req_friendly_name': 'useSaharaCometConsentPostPromptOutcomeServerMutation',
        'variables': variables,
        'server_timestamps': 'true',
        'doc_id': '9822638027828705'
    }

    gql_headers = {
        "content-type": "application/x-www-form-urlencoded",
        "cookie": cookie_string,
        "referer": url,
        "user-agent": user_agent,
        "x-csrftoken": csrftoken,
        "x-fb-lsd": lsd.group(1) if lsd else "",
        "x-ig-app-id": "1217981644879628",
        "x-requested-with": "XMLHttpRequest"
    }

    return http_call('https://www.instagram.com/api/graphql/', post_data, gql_headers, 'POST')

def fetch_voucher_with_retry(creator_token, ip, max_retries=30, retry_delay=4):
    url = "https://shein-creator-backend-151437891745.asia-south1.run.app/api/v1/user"
    headers = {
        "Authorization": f"Bearer {creator_token}",
        "User-Agent": "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36",
        "Content-Type": "application/json",
        "Origin": "https://sheinverse.galleri5.com",
        "Referer": "https://sheinverse.galleri5.com/",
        "X-Forwarded-For": ip
    }

    for _ in range(max_retries):
        res = http_call(url, None, headers, "GET")
        try:
            result = json.loads(res['body'])
            if result.get('message') == 'Profile fetched successfully':
                user_data = result.get('user_data', {})
                if user_data.get('voucher_data', {}).get('voucher_code'):
                    return user_data['voucher_data']
                
                vouchers = user_data.get('vouchers', [])
                if vouchers and vouchers[0].get('voucher_code'):
                    return vouchers[0]
        except: pass
        time.sleep(retry_delay)
    return None

def handle_instagram_linking(chat_id, message_id=None, mode='connect'):
    user_data = get_or_create_user_data(chat_id)
    cookie_raw = user_data.get('instagram_cookie_raw')
    creator_token = user_data.get('creator_token')
    current_mobile = user_data.get('current_mobile')

    if not cookie_raw or not creator_token or not current_mobile:
        bot.send_message(chat_id, "❌ Missing data. Please select an account first.")
        return

    # Validate Cookie
    validity = validate_instagram_cookie(cookie_raw)
    if not validity['valid']:
        bot.send_message(chat_id, f"❌ Invalid cookie format!\nMissing: {validity.get('missing')}\n\nPlease send valid cookies.")
        user_data['step'] = 'ask_instagram_cookie_unlink' if mode == 'unlink' else 'ask_instagram_cookie'
        save_user_data(chat_id, user_data)
        return

    bot.send_message(chat_id, "⏳ Connecting Instagram account...\n⚠️ Max 5 retries. Send /cancel to stop.")
    user_data['cookie_workflow_active'] = True
    save_user_data(chat_id, user_data)

    max_retries = 5
    
    for retry in range(1, max_retries + 1):
        # Check cancellation
        user_data = get_or_create_user_data(chat_id)
        if not user_data.get('cookie_workflow_active'):
            bot.send_message(chat_id, "❌ Cancelled by user.")
            return
        
        bot.send_message(chat_id, f"🔄 Attempt {retry}/{max_retries} - Getting OAuth code...")
        
        ip = rand_ip()
        ad_id = rand_hex(16)
        
        insta_res = get_instagram_oauth(cookie_raw, creator_token, ad_id, ip, mode)
        
        if not insta_res['success']:
            if insta_res['http_code'] == 403:
                bot.send_message(chat_id, "❌ Akamai blocked (403). Waiting 12s...")
                time.sleep(12)
                continue
            bot.send_message(chat_id, f"⚠️ Error: {insta_res.get('error')}\nRetrying in 6s...")
            time.sleep(6)
            continue

        # Extract OAuth Code from GraphQL response
        oauth_code = None
        try:
            insta_json = json.loads(insta_res['body'])
            save_instagram_data(chat_id, insta_json)
            
            # Navigate deep nested JSON
            uri = insta_json['data']['post_prompt_outcome']['finish_flow_action']['link_uri']['uri']
            parsed = urlparse(uri)
            q = parse_qs(parsed.query)
            if 'u' in q:
                decoded_url = unquote(q['u'][0])
                fp = urlparse(decoded_url)
                q2 = parse_qs(fp.query)
                if 'code' in q2:
                    oauth_code = q2['code'][0]
        except Exception as e:
            pass

        if not oauth_code:
            bot.send_message(chat_id, "⚠️ No OAuth code found (cookie might be expired or account linked). Retrying...")
            time.sleep(7)
            continue

        bot.send_message(chat_id, "✅ OAuth code obtained! Connecting to Shein backend...")
        
        # Send to Shein
        shein_url = "https://shein-creator-backend-151437891745.asia-south1.run.app/api/v5/instagram"
        shein_headers = {
            "Authorization": f"Bearer {creator_token}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36",
            "Origin": "https://sheinverse.galleri5.com",
            "Referer": "https://sheinverse.galleri5.com/"
        }
        
        shein_payload = {"code": oauth_code, "redirectUri": "https://sheinverse.galleri5.com/instagram"}
        
        shein_res = http_call(shein_url, shein_payload, shein_headers, "POST")
        
        if not shein_res['success']:
            bot.send_message(chat_id, "❌ Shein API connection failed. Retrying...")
            time.sleep(8)
            continue
            
        try:
            shein_json = json.loads(shein_res['body'])
            save_instagram_data(chat_id, shein_json)
            
            if shein_json.get('message') != 'Instagram connection successful':
                bot.send_message(chat_id, f"❌ Shein says: {shein_json.get('message')}. Retrying...")
                time.sleep(8)
                continue
                
    
