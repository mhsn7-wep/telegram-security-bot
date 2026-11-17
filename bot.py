import os
import logging
import asyncio
import urllib.parse
import sqlite3
from datetime import datetime
import io
import aiohttp
from bs4 import BeautifulSoup
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CallbackQueryHandler, CommandHandler, ContextTypes, MessageHandler, filters

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

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

async def check_security_headers(url):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=5, ssl=False) as response:
                headers = response.headers
                server = headers.get('Server', 'غير معروف / محجوب')
                
                security_headers = {
                    'Content-Security-Policy': 'يحمي من XSS وحقن النطاقات',
                    'X-Frame-Options': 'يحمي من هجمات Clickjacking',
                    'X-Content-Type-Options': 'يحمي من استنتاج الأنواع الخبيثة',
                    'Strict-Transport-Security': 'يشفر الاتصالات عبر HSTS'
                }
                
                score = 100
                result = f"🛡️ **تحليل الخادم ورؤوس الأمان:**\n"
                result += f"  🌐 نوع الخادم: `{server}`\n\n"
                
                for header, desc in security_headers.items():
                    if header in headers:
                        result += f"  ✅ `{header}`: آمن\n"
                    else:
                        score -= 20
                        result += f"  ❌ `{header}`: مفقود (ثغرة محتملة)\n"
                return result, score
    except Exception as e:
        return f"❌ خطأ في فحص الرؤوس: {str(e)}", 0

async def check_sensitive_files(base_url):
    base_url = base_url.rstrip('/')
    result = "📁 **نتائج فحص المسارات والمجلدات الدقيقة:**\n"
    found_count = 0
    
    async with aiohttp.ClientSession() as session:
        tasks = [fetch(session, base_url + path) for path in SENSITIVE_PATHS]
        responses = await asyncio.gather(*tasks)
        
        for path, (status, _) in zip(SENSITIVE_PATHS, responses):
            if status == 200:
                found_count += 1
                result += f"  🚨 [مكشوف تماماً]: `{base_url + path}` (رمز الاستجابة: 200)\n"
            elif status == 403:
                result += f"  🔒 [مغلق/محمي]: `{base_url + path}` (رمز الاستجابة: 403)\n"
                
    if found_count == 0:
        result += "  ✅ لم يتم كشف مسارات حساسة عامة ظاهرة.\n"
    return result, found_count

async def check_sqli(url):
    payload = "' OR '1'='1"
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    
    if not query_params:
        return "⚠️ **SQL Injection:** الرابط لا يحتوي على معاملات (Parameters) واضحة للفحص المباشر.", False
    
    vulnerable = False
    result = "💉 **نتائج فحص المعاملات الدقيقة:**\n"
    
    async with aiohttp.ClientSession() as session:
        for param in query_params:
            test_url = url.replace(f"{param}={query_params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
            status, html = await fetch(session, test_url)
            if html:
                sql_errors = ["sql syntax", "mysql", "syntax error", "sqlite", "postgresql", "ora-"]
                if any(err in html.lower() for err in sql_errors):
                    vulnerable = True
                    result += f"  🚨 [مكان الثغرة بالتحديد]:\n"
                    result += f"     - المعامل المصاب: `{param}`\n"
                    result += f"     - الرابط الفعلي المختبر: `{test_url}`\n"
                    
    if not vulnerable:
        result += "  ✅ جميع المعاملات المفحوصة لم تظهر استجابة خطأ واضحة.\n"
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
    
    result = f"🚪 **فحص البنية التحتية والمنافذ الحساسة:**\n"
    tasks = [check_port(domain, port) for port in ports]
    results = await asyncio.gather(*tasks)
    
    open_ports = 0
    for port, is_open in results:
        if is_open:
            result += f"  🟢 المنفذ `{port}`: مفتوح\n"
            open_ports += 1
        else:
            result += f"  🔴 المنفذ `{port}`: مغلق\n"
    return result, open_ports

def generate_pdf_report(url, report_text):
    pdf_buffer = io.BytesIO()
    c = canvas.Canvas(pdf_buffer, pagesize=letter)
    width, height = letter
    
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 50, "Falcon Eye (عين الصقر) - Security Audit Report")
    c.setFont("Helvetica", 10)
    c.drawString(50, height - 70, f"Target URL: {url}")
    c.drawString(50, height - 85, f"Generated At: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    c.line(50, height - 95, width - 50, height - 95)
    
    c.setFont("Helvetica", 9)
    text_object = c.beginText(50, height - 120)
    text_object.setLeading(14)
    
    clean_text = report_text.replace('*', '').replace('`', '').replace('🛡️', '').replace('📁', '').replace('💉', '').replace('🚪', '')
    
    for line in clean_text.split('\n'):
        if len(line) > 90:
            line = line[:90] + "..."
        text_object.textLine(line)
        
    c.drawText(text_object)
    c.save()
    pdf_buffer.seek(0)
    return pdf_buffer

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [[InlineKeyboardButton("🦅 ابدأ الفحص الدقيق مع عين الصقر", callback_data="intro")]]
    await update.message.reply_text(
        "👋 **أهلاً بك في بوت (عين الصقر 🦅 - Falcon Eye)**\n\n"
        "أنا نظامك الأمني الذكي والمتطور، أمتلك نظرة حادة لاكتشاف الثغرات وتحديد أماكن الخلل بدقة تامة.\n\n"
        "🎯 **كيف أعمل؟**\n"
        "فقط أرسل لي رابط الموقع المراد فحصه (مثال: `https://example.com/?id=1`) وسأقوم بتمحيصه وتحديد الأماكن بدقة تامة وإرسال تقرير PDF رسمي لك.",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode="Markdown"
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        await update.message.reply_text("❌ يرجى إرسال رابط صحيح يبدأ بـ `http://` أو `https://`")
        return
        
    context.user_data['target_url'] = url
    keyboard = [[InlineKeyboardButton("⚡ إطلاق عين الصقر للفحص الشامل وتوليد PDF", callback_data="run_deep_scan")]]
    await update.message.reply_text(
        f"🦅 **تم رصد الهدف بنجاح بواسطة عين الصقر:**\n`{url}`\n\nاضغط الزر أدناه لبدء عملية المسح الأمني الدقيق:",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode="Markdown"
    )

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    if query.data == "run_deep_scan" or query.data == "intro":
        url = context.user_data.get('target_url')
        if not url:
            await query.edit_message_text("⚠️ يرجى إرسال رابط الموقع أولاً كتابةً في المحادثة.")
            return
            
        await query.edit_message_text(f"🦅 **عين الصقر تفتح عينيها الآن...**\nجاري فحص الهدف وتحديد الأماكن بدقة:\n`{url}`\nيرجى الانتظار قليلاً...", parse_mode="Markdown")
        
        headers_res, headers_score = await check_security_headers(url)
        sensitive_res, sensitive_count = await check_sensitive_files(url)
        sqli_res, sqli_vuln = await check_sqli(url)
        ports_res, open_ports_count = await scan_ports(url)
        
        risk_score = headers_score - (sensitive_count * 15) - (30 if sqli_vuln else 0) - (open_ports_count * 5)
        risk_label = "حرج 🔴" if risk_score < 40 else ("متوسط 🟡" if risk_score < 70 else "آمن نسبياً 🟢")
        
        full_report = f"====================================\n"
        full_report += f" FALCON EYE (عين الصقر) SECURITY AUDIT\n"
        full_report += f" Target: {url}\n"
        full_report += f" Risk Status: {risk_label} (Score: {max(0, risk_score)}/100)\n"
        full_report += f"====================================\n\n"
        full_report += headers_res + "\n------------------------------------\n"
        full_report += sensitive_res + "\n------------------------------------\n"
        full_report += sqli_res + "\n------------------------------------\n"
        full_report += ports_res
        
        conn = sqlite3.connect('scanner_vault.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO scans (user_id, target_url, scan_date, risk_level, details) VALUES (?, ?, ?, ?, ?)",
                       (query.from_user.id, url, datetime.now().strftime('%Y-%m-%d %H:%M'), risk_label, full_report))
        conn.commit()
        conn.close()
        
        await context.bot.send_message(
            chat_id=query.message.chat_id,
            text=f"🦅 **انتهت مهمة عين الصقر بنجاح تام!**\n\n- تقييم الأمان العام: **{risk_label}**\n- الملفات المكشوفة: `{sensitive_count}`\n- المنافذ المفتوحة: `{open_ports_count}`\n\nجاري إعداد وإرسال تقرير الـ PDF الرسمي...",
            parse_mode="Markdown"
        )
        
        pdf_file = generate_pdf_report(url, full_report)
        clean_domain = url.replace("https://", "").replace("http://", "").split("/")[0].replace(":", "_")
        
        await context.bot.send_document(
            chat_id=query.message.chat_id,
            document=pdf_file,
            filename=f"FalconEye_Report_{clean_domain}.pdf",
            caption=f"🦅📄 تقرير عين الصقر الرسمي لـ: {url}"
        )

if __name__ == '__main__':
    app = ApplicationBuilder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_message))
    app.add_handler(CallbackQueryHandler(button_callback))
    
    print("عين الصقر يحلق الآن ويعمل بنجاح...")
    app.run_polling()
