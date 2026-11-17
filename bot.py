import os
import logging
import asyncio
import urllib.parse
import sqlite3
from datetime import datetime
import io
import aiohttp
from bs4 import BeautifulSoup

# مكتبات تصميم الـ PDF مع دعم الخط العربي
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import urllib.request

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CallbackQueryHandler, CommandHandler, ContextTypes, MessageHandler, filters

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

# تحميل خط عربي رسمي لكي يظهر تقرير الـ PDF بالعربي بوضوح تام بدون أي حجب
FONT_PATH = "Amiri-Regular.ttf"
if not os.path.exists(FONT_PATH):
    try:
        font_url = "https://github.com/google/fonts/raw/main/ofl/amiri/Amiri-Regular.ttf"
        urllib.request.urlretrieve(font_url, FONT_PATH)
    except:
        pass

def init_db():
    conn = sqlite3.connect('scanner_vault.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            target_url TEXT,
            scan_date TEXT,
            risk_level TEXT,
            details TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

SENSITIVE_PATHS = [
    "/robots.txt", "/sitemap.xml", "/admin/", "/administrator/", 
    "/.git/config", "/backup.zip", "/config.php", "/wp-login.php", "/api/v1/"
]

async def fetch(session, url):
    try:
        async with session.get(url, timeout=5, ssl=False) as response:
            return response.status, await response.text()
    except:
        return None, None

# فحوصات باللغة الإنجليزية وبدون حجب للنتائج
async def check_security_headers(url):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=5, ssl=False) as response:
                headers = response.headers
                server = headers.get('Server', 'Unknown / Hidden')
                
                security_headers = [
                    'Content-Security-Policy',
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'Strict-Transport-Security'
                ]
                
                score = 100
                result = f"🛡️ SECURITY HEADERS ANALYSIS:\n"
                result += f"  - Server Type: {server}\n\n"
                
                for header in security_headers:
                    if header in headers:
                        result += f"  [SECURE] {header}: Present\n"
                    else:
                        score -= 20
                        result += f"  [VULNERABLE] {header}: Missing\n"
                return result, score
    except Exception as e:
        return f"❌ Headers Check Error: {str(e)}", 0

async def check_sensitive_files(base_url):
    base_url = base_url.rstrip('/')
    result = "📁 SENSITIVE FILES & DIRS SCAN:\n"
    found_count = 0
    
    async with aiohttp.ClientSession() as session:
        tasks = [fetch(session, base_url + path) for path in SENSITIVE_PATHS]
        responses = await asyncio.gather(*tasks)
        
        for path, (status, _) in zip(SENSITIVE_PATHS, responses):
            if status == 200:
                found_count += 1
                result += f"  [EXPOSED]: {base_url + path} (Status: 200)\n"
            elif status == 403:
                result += f"  [PROTECTED]: {base_url + path} (Status: 403)\n"
                
    if found_count == 0:
        result += "  [SAFE] No public sensitive files exposed.\n"
    return result, found_count

async def check_sqli(url):
    payload = "' OR '1'='1"
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    
    if not query_params:
        return "⚠️ SQL Injection: URL has no parameters for direct testing.", False
    
    vulnerable = False
    result = "💉 SQL INJECTION PARAMETER SCAN:\n"
    
    async with aiohttp.ClientSession() as session:
        for param in query_params:
            test_url = url.replace(f"{param}={query_params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
            status, html = await fetch(session, test_url)
            if html:
                sql_errors = ["sql syntax", "mysql", "syntax error", "sqlite", "postgresql", "ora-"]
                if any(err in html.lower() for err in sql_errors):
                    vulnerable = True
                    result += f"  [EXACT VULNERABILITY LOCATION]:\n"
                    result += f"     - Vulnerable Parameter: {param}\n"
                    result += f"     - Exact Tested URL: {test_url}\n"
                    
    if not vulnerable:
        result += "  [SAFE] No clear SQL error responses detected on parameters.\n"
    return result, vulnerable

async def check_port(domain, port):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(domain, port), timeout=0.8)
        writer.close()
        await writer.wait_closed()
        return port, True
    except:
        return port, False

async def scan_ports(url):
    domain = url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    ports = [21, 22, 25, 80, 443, 3306, 3389, 8080]
    
    result = f"🚪 INFRASTRUCTURE & PORT SCAN:\n"
    tasks = [check_port(domain, port) for port in ports]
    results = await asyncio.gather(*tasks)
    
    open_ports = 0
    for port, is_open in results:
        if is_open:
            result += f"  [OPEN] Port {port}\n"
            open_ports += 1
        else:
            result += f"  [CLOSED] Port {port}\n"
    return result, open_ports

# دالة توليد تقرير PDF مترجم بالكامل للغة العربية الفصحى (بدون أي حجب)
def generate_arabic_pdf_report(url, safety_percent, risk_text, raw_details):
    pdf_buffer = io.BytesIO()
    c = canvas.Canvas(pdf_buffer, pagesize=letter)
    width, height = letter
    
    try:
        if os.path.exists(FONT_PATH):
            pdfmetrics.registerFont(TTFont('ArabicFont', FONT_PATH))
            c.setFont('ArabicFont', 14)
        else:
            c.setFont("Helvetica-Bold", 12)
    except:
        c.setFont("Helvetica-Bold", 12)
        
    # ترويسة التقرير باللغة العربية
    c.drawString(50, height - 40, "منصة عين الصقر الأمنية - تقرير الفحص والتقييم الشامل")
    c.setFont('ArabicFont', 10) if os.path.exists(FONT_PATH) else c.setFont("Helvetica", 10)
    c.drawString(50, height - 65, f"الرابط المستهدف: {url}")
    c.drawString(50, height - 80, f"تاريخ وقت التقرير: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    c.drawString(50, height - 95, f"نسبة الأمان للموقع: {safety_percent}%")
    c.drawString(50, height - 110, f"تقييم الخطورة: {risk_text}")
    c.line(50, height - 120, width - 50, height - 120)
    
    text_object = c.beginText(50, height - 145)
    text_object.setLeading(16)
    
    if os.path.exists(FONT_PATH):
        text_object.setFont('ArabicFont', 10)
    else:
        text_object.setFont("Helvetica", 9)
        
    # ترجمة وشرح النتائج باللغة العربية داخل ملف الـ PDF ليكون واضحاً وخالياً من الحجب
    pdf_content_ar = [
        "==============================================",
        "          تفاصيل الفحص التقني والأمني          ",
        "==============================================",
        "1. تحليل رؤوس الأمان (Security Headers):",
        "   - تم فحص بروتوكولات الحماية والرؤوس الأساسية للخادم.",
        "   - الأجزاء المفقودة تمثل نقاط ضعف قد تستغل في الهجمات.",
        "",
        "2. فحص المسارات والمجلدات المخفية (Dirbusting):",
        "   - تم فحص الملفات الحساسة وملفات الإعدادات العامة.",
        "   - أي رابط يظهر بحالة (200) يعني أنه مكشوف للعامة.",
        "",
        "3. فحص المعاملات وثغرات قواعد البيانات (SQLi):",
        "   - تم اختبار معاملات الروابط للتأكد من تعقيم المدخلات.",
        "   - ظهور مسار محدد يعني وجود ثغرة حقن محتملة تستوجب المعالجة.",
        "",
        "4. فحص المنافذ والبنية التحتية (Port Scan):",
        "   - تم فحص المنافذ الحساسة المفتوحة على الخادم.",
        "----------------------------------------------",
        " ملاحظة هامة: هذا التقرير صدر تلقائياً عبر نظام عين الصقر",
        " لتقييم وفحص أمن الموقع بدقة عالية وتحديد الأماكن بدقة."
    ]
    
    for line in pdf_content_ar:
        try:
            text_object.textLine(line)
        except:
            pass
            
    c.drawText(text_object)
    c.save()
    pdf_buffer.seek(0)
    return pdf_buffer

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [[InlineKeyboardButton("🦅 Start Falcon Eye", callback_data="intro")]]
    await update.message.reply_text(
        "👋 **Welcome to Falcon Eye Bot (عين الصقر 🦅)**\n\n"
        "Professional Automated Vulnerability & Security Scanner.\n"
        "Send your target URL (e.g., `https://example.com`) to begin.",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode="Markdown"
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        await update.message.reply_text("❌ Please send a valid URL starting with `http://` or `https://`")
        return
        
    context.user_data['target_url'] = url
    
    keyboard = [
        [InlineKeyboardButton("📊 Full Audit & Safety Rate", callback_data="run_full_audit")],
        [InlineKeyboardButton("🚨 Vulnerabilities & Breach Check", callback_data="run_breach_check")],
        [InlineKeyboardButton("📄 Export Official Arabic PDF Report", callback_data="run_pdf_report")]
    ]
    
    await update.message.reply_text(
        f"🦅 **Target Captured by Falcon Eye:**\n`{url}`\n\n"
        f"Choose an option from the audit menu below:",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode="Markdown"
    )

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    url = context.user_data.get('target_url')
    if not url and query.data != "intro":
        await query.edit_message_text("⚠️ Please send the target URL first in chat.")
        return
        
    if query.data == "intro":
        await query.edit_message_text(
            "🦅 **Falcon Eye is Ready!**\n\nSend any URL now to view the inspection menu.",
            parse_mode="Markdown"
        )
        return

    if query.data in ["run_full_audit", "run_breach_check", "run_pdf_report"]:
        await query.edit_message_text(f"🦅 **Falcon Eye Scanning Target...**\n`{url}`\nPlease wait...", parse_mode="Markdown")
        
        headers_res, headers_score = await check_security_headers(url)
        sensitive_res, sensitive_count = await check_sensitive_files(url)
        sqli_res, sqli_vuln = await check_sqli(url)
        ports_res, open_ports_count = await scan_ports(url)
        
        risk_score = headers_score - (sensitive_count * 15) - (30 if sqli_vuln else 0) - (open_ports_count * 5)
        final_safety_percentage = max(0, risk_score)
        
        if final_safety_percentage < 40:
            risk_label_en = "Critical (High risk of breach or vulnerabilities)"
            risk_label_ar = "حرج (مستوى خطورة مرتفع واحتمالية وجود ثغرات استغلالية)"
        elif final_safety_percentage < 70:
            risk_label_en = "Medium (Needs security hardening)"
            risk_label_ar = "متوسط (يحتاج إلى تحصين وإغلاق ثغرات)"
        else:
            risk_label_en = "Relatively Safe (Good security configurations)"
            risk_label_ar = "آمن نسبياً (إعدادات الأمان جيدة ومقبولة)"
            
        full_details_en = f"{headers_res}\n{sensitive_res}\n{sqli_res}\n{ports_res}"
        
        conn = sqlite3.connect('scanner_vault.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO scans (user_id, target_url, scan_date, risk_level, details) VALUES (?, ?, ?, ?, ?)",
                       (query.from_user.id, url, datetime.now().strftime('%Y-%m-%d %H:%M'), risk_label_en, full_details_en))
        conn.commit()
        conn.close()
        
        # رسالة تيليجرام بالإنجليزية وبدون أي حجب للنتائج الدقيقة
        summary_text = (
            f"🎯 **Falcon Eye Audit Results:**\n"
            f"🔗 Target: `{url}`\n\n"
            f"📊 **Safety Rate:** `{final_safety_percentage}%`\n"
            f"⚠️ **Risk Level:** {risk_label_en}\n\n"
            f"```text\n"
            f"{full_details_en}\n"
            f"```\n"
            f"✨ Scan completed successfully without blocking any results!"
        )
        
        if len(summary_text) > 4096:
            summary_text = summary_text[:4000] + "\n[Output Truncated due to length]"

        await context.bot.send_message(
            chat_id=query.message.chat_id,
            text=summary_text,
            parse_mode="Markdown"
        )
        
        # إرسال تقرير الـ PDF باللغة العربية الفصحى الرسمية
        if query.data in ["run_full_audit", "run_pdf_report"]:
            pdf_file = generate_arabic_pdf_report(url, final_safety_percentage, risk_label_ar, full_details_en)
            clean_domain = url.replace("https://", "").replace("http://", "").split("/")[0].replace(":", "_")
            
            await context.bot.send_document(
                chat_id=query.message.chat_id,
                document=pdf_file,
                filename=f"FalconEye_Arabic_Report_{clean_domain}.pdf",
                caption=f"🦅📄 تقرير عين الصقر الرسمي (باللغة العربية) لـ: {url}"
            )

if __name__ == '__main__':
    app = ApplicationBuilder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_message))
    app.add_handler(CallbackQueryHandler(button_callback))
    
    print("Falcon Eye is running successfully...")
    app.run_polling()
