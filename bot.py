import os
import logging
import asyncio
import urllib.parse
import sqlite3
from datetime import datetime
import io
import ssl
import socket
import json
import re
import aiohttp
from bs4 import BeautifulSoup

# مكتبات تصميم الـ PDF المحدثة والمستقرة
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

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
    "/.git/config", "/backup.zip", "/config.php", "/wp-login.php", "/api/v1/",
    "/.env", "/config.json", "/database.sql", "/backup.tar.gz"
]

async def fetch(session, url):
    try:
        async with session.get(url, timeout=5, ssl=False) as response:
            return response.status, await response.text()
    except:
        return None, None

async def check_ssl_certificate(url):
    domain = url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        def get_cert():
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    return ssock.getpeercert()
        
        cert = await asyncio.to_thread(get_cert)
        not_after = cert.get('notAfter')
        
        result = f"SSL/TLS CERTIFICATE CHECK:\n"
        result += f"  [SECURE] Valid SSL Certificate detected for domain: {domain}\n"
        result += f"  - Expires on: {not_after}\n"
        return result, 100
    except Exception as e:
        return f"SSL/TLS CERTIFICATE CHECK:\n  [VULNERABLE/WARNING] SSL Issue or HTTP-only: {str(e)}\n", 50

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
                result = f"SECURITY HEADERS:\n"
                result += f"  - Server: {server}\n"
                
                missing_headers = []
                for header in security_headers:
                    if header in headers:
                        result += f"  [SECURE] {header}: Present\n"
                    else:
                        score -= 20
                        missing_headers.append(header)
                        result += f"  [VULNERABLE] {header}: Missing\n"
                        
                if missing_headers:
                    result += f"  -> Vulnerability Type: Missing Security Headers\n"
                    result += f"  -> Risk Level: Medium\n"

                return result, max(0, score)
    except Exception as e:
        return f"Headers Check Error: {str(e)}", 0

async def check_sensitive_files(base_url):
    base_url = base_url.rstrip('/')
    result = "SENSITIVE FILES & DIRS (Dirbusting):\n"
    found_count = 0
    
    async with aiohttp.ClientSession() as session:
        tasks = [fetch(session, base_url + path) for path in SENSITIVE_PATHS]
        responses = await asyncio.gather(*tasks)
        
        for path, (status, _) in zip(SENSITIVE_PATHS, responses):
            if status == 200:
                found_count += 1
                result += f"  [EXPOSED - CRITICAL]: {base_url + path} (Status: 200)\n"
            elif status == 403:
                result += f"  [PROTECTED]: {base_url + path} (Status: 403)\n"
                
    if found_count > 0:
        result += f"  -> Vulnerability Type: Information Disclosure\n"
        result += f"  -> Risk Level: Critical\n"
    else:
        result += "  [SAFE] No critical public sensitive files exposed.\n"
        
    return result, found_count

async def check_sqli(url):
    payload = "' OR '1'='1"
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    
    if not query_params:
        return "SQL INJECTION: URL has no parameters.", False
    
    vulnerable = False
    result = "SQL INJECTION PARAMETER SCAN:\n"
    
    async with aiohttp.ClientSession() as session:
        for param in query_params:
            test_url = url.replace(f"{param}={query_params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
            status, html = await fetch(session, test_url)
            if html:
                sql_errors = ["sql syntax", "mysql", "syntax error", "sqlite", "postgresql", "ora-"]
                if any(err in html.lower() for err in sql_errors):
                    vulnerable = True
                    result += f"  [VULNERABLE] Parameter: {param} (URL: {test_url})\n"
                    
    if vulnerable:
        result += f"  -> Vulnerability Type: SQL Injection (SQLi)\n"
        result += f"  -> Risk Level: Critical\n"
    else:
        result += "  [SAFE] No SQL errors detected.\n"
        
    return result, vulnerable

async def check_xss(url):
    payload = "<script>alert('XSS')</script>"
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    
    if not query_params:
        return "REFLECTED XSS: URL has no parameters.", False
        
    vulnerable = False
    result = "REFLECTED XSS SCAN:\n"
    
    async with aiohttp.ClientSession() as session:
        for param in query_params:
            test_url = url.replace(f"{param}={query_params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
            status, html = await fetch(session, test_url)
            if html and payload in html:
                vulnerable = True
                result += f"  [VULNERABLE] Parameter: {param}\n"
                
    if vulnerable:
        result += f"  -> Vulnerability Type: Reflected XSS\n"
        result += f"  -> Risk Level: High\n"
    else:
        result += "  [SAFE] No payload reflection.\n"
        
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
    
    result = f"PORT SCAN:\n"
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

# دالة توليد الـ PDF المحدثة باستخدام SimpleDocTemplate لمنع المربعات السوداء
def generate_pdf_report(url, safety_percent, risk_text, raw_details):
    pdf_buffer = io.BytesIO()
    doc = SimpleDocTemplate(pdf_buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    story = []
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=14, textColor='black', spaceAfter=10)
    normal_style = ParagraphStyle('NormalStyle', parent=styles['Normal'], fontSize=8, leading=12, textColor='black')
    
    story.append(Paragraph("Falcon Eye Enterprise Security Report", title_style))
    story.append(Paragraph(f"<b>Target URL:</b> {url}", normal_style))
    story.append(Paragraph(f"<b>Generated At:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    story.append(Paragraph(f"<b>Safety Score:</b> {safety_percent}%", normal_style))
    story.append(Paragraph(f"<b>Risk Level:</b> {risk_text}", normal_style))
    story.append(Spacer(1, 15))
    
    for line in raw_details.split('\n'):
        clean_line = "".join([ch for ch in line if ord(ch) < 128])
        if not clean_line.strip():
            continue
        clean_line = clean_line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        story.append(Paragraph(clean_line, normal_style))
        
    doc.build(story)
    pdf_buffer.seek(0)
    return pdf_buffer

def generate_json_report(url, safety_percent, risk_text, raw_details):
    data = {
        "target_url": url,
        "scan_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "safety_score": f"{safety_percent}%",
        "risk_level": risk_text,
        "scan_details": raw_details
    }
    json_bytes = json.dumps(data, indent=4).encode('utf-8')
    return io.BytesIO(json_bytes)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("🚀 Start Falcon Eye v2.0", callback_data="intro")],
        [InlineKeyboardButton("📊 Control Panel / History", callback_data="show_history")]
    ]
    # **العبارة الترحيبية الجديدة والمميزة لتتأكد من التحديث**
    await update.message.reply_text(
        "🦅 **[UPDATED] Welcome to Falcon Eye Security Bot (v2.0)**\n\n"
        "✨ Status: Successfully updated with Clean PDF Engine & SSL Check!\n"
        "🔗 Send your target URL (e.g., `https://example.com`) right now to begin scanning.",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode="Markdown"
    )

async def history_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    conn = sqlite3.connect('scanner_vault.db')
    cursor = conn.cursor()
    cursor.execute("SELECT target_url, scan_date, risk_level FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT 5", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        await update.message.reply_text("No previous scans found.")
        return
        
    text = "Your Recent Scans:\n\n"
    for row in rows:
        text += f"Target: {row[0]}\nDate: {row[1]}\nRisk: {row[2]}\n-------------------\n"
        
    keyboard = [[InlineKeyboardButton("Clear History", callback_data="clear_history")]]
    await update.message.reply_text(text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        await update.message.reply_text("Please send a valid URL starting with http:// or https://")
        return
        
    context.user_data['target_url'] = url
    
    keyboard = [
        [InlineKeyboardButton("Run Full Deep Audit", callback_data="run_full_audit")],
        [InlineKeyboardButton("Export Clean PDF Report", callback_data="run_pdf_report")],
        [InlineKeyboardButton("Export JSON Report", callback_data="run_json_report")],
        [InlineKeyboardButton("Main Dashboard", callback_data="intro")]
    ]
    
    await update.message.reply_text(
        f"Target Captured:\n{url}\n\nSelect an option:",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode="Markdown"
    )

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    if query.data == "show_history":
        user_id = query.from_user.id
        conn = sqlite3.connect('scanner_vault.db')
        cursor = conn.cursor()
        cursor.execute("SELECT target_url, scan_date, risk_level FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT 5", (user_id,))
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            await query.edit_message_text("No previous scans found.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Back", callback_data="intro")]]))
            return
            
        text = "Recent Scans History:\n\n"
        for row in rows:
            text += f"{row[0]}\n{row[1]} | {row[2]}\n\n"
        keyboard = [
            [InlineKeyboardButton("Clear History", callback_data="clear_history")],
            [InlineKeyboardButton("Back", callback_data="intro")]
        ]
        await query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")
        return

    if query.data == "clear_history":
        user_id = query.from_user.id
        conn = sqlite3.connect('scanner_vault.db')
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
        await query.edit_message_text("History cleared successfully!", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Back", callback_data="intro")]]))
        return

    if query.data == "intro":
        keyboard = [
            [InlineKeyboardButton("Start Scanning", callback_data="intro_msg")],
            [InlineKeyboardButton("Control Panel / History", callback_data="show_history")]
        ]
        await query.edit_message_text("Falcon Eye v2.0 Dashboard Ready.\nSend any target URL to begin.", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")
        return

    url = context.user_data.get('target_url')
    if not url:
        await query.edit_message_text("Please send the target URL first.")
        return

    if query.data in ["run_full_audit", "run_pdf_report", "run_json_report"]:
        await query.edit_message_text(f"Falcon Eye Deep Scanning & SSL Check...\n{url}\nPlease wait...", parse_mode="Markdown")
        
        ssl_res, ssl_score = await check_ssl_certificate(url)
        headers_res, headers_score = await check_security_headers(url)
        sensitive_res, sensitive_count = await check_sensitive_files(url)
        sqli_res, sqli_vuln = await check_sqli(url)
        xss_res, xss_vuln = await check_xss(url)
        ports_res, open_ports_count = await scan_ports(url)
        
        risk_score = headers_score - (sensitive_count * 15) - (30 if sqli_vuln else 0) - (25 if xss_vuln else 0) - (open_ports_count * 3)
        final_safety_percentage = max(0, risk_score)
        
        if final_safety_percentage < 40 or sqli_vuln or xss_vuln:
            risk_label = "Critical (High risk of breaches)"
        elif final_safety_percentage < 70:
            risk_label = "Medium (Needs security hardening)"
        else:
            risk_label = "Relatively Safe (Good security baseline)"
            
        full_details = f"{ssl_res}\n{headers_res}\n{sensitive_res}\n{sqli_res}\n{xss_res}\n{ports_res}"
        
        conn = sqlite3.connect('scanner_vault.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO scans (user_id, target_url, scan_date, risk_level, details) VALUES (?, ?, ?, ?, ?)",
                       (query.from_user.id, url, datetime.now().strftime('%Y-%m-%d %H:%M'), risk_label, full_details))
        conn.commit()
        conn.close()
        
        summary_text = (
            f"Falcon Eye Audit Results & SSL Check:\n"
            f"Target: {url}\n\n"
            f"Safety Rate: {final_safety_percentage}%\n"
            f"Risk Level: {risk_label}\n\n"
            f"```text\n"
            f"{full_details}\n"
            f"```"
        )
        
        if len(summary_text) > 4096:
            summary_text = summary_text[:4000] + "\n[Output Truncated]"

        await context.bot.send_message(
            chat_id=query.message.chat_id,
            text=summary_text,
            parse_mode="Markdown"
        )
        
        clean_domain = url.replace("https://", "").replace("http://", "").split("/")[0].replace(":", "_")
        
        if query.data in ["run_full_audit", "run_pdf_report"]:
            pdf_file = generate_pdf_report(url, final_safety_percentage, risk_label, full_details)
            await context.bot.send_document(
                chat_id=query.message.chat_id,
                document=pdf_file,
                filename=f"Security_Report_{clean_domain}.pdf",
                caption=f"Official PDF Security Report for: {url}"
            )
            
        if query.data == "run_json_report":
            json_file = generate_json_report(url, final_safety_percentage, risk_label, full_details)
            await context.bot.send_document(
                chat_id=query.message.chat_id,
                document=json_file,
                filename=f"Security_Report_{clean_domain}.json",
                caption=f"Official JSON Report for: {url}"
            )

if __name__ == '__main__':
    app = ApplicationBuilder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("history", history_command))
    app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_message))
    app.add_handler(CallbackQueryHandler(button_callback))
    
    print("Falcon Eye Upgraded & Running successfully...")
    app.run_polling()
