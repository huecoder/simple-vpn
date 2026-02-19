#!/usr/bin/env python3
"""
VPN Telegram Bot Panel v2.0
- Управление клиентами (добавить/удалить/просмотреть)
- Лимиты: по гигабайтам и по времени (дни)
- Ротация SNI
- Статистика трафика через Xray API
"""

import os, json, logging, subprocess, io, sys, uuid
from datetime import datetime, timedelta
from pathlib import Path

try:
    import qrcode
    from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.ext import (
        Application, CommandHandler, CallbackQueryHandler,
        ContextTypes, ConversationHandler, MessageHandler, filters
    )
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "-q",
                    "python-telegram-bot", "qrcode", "pillow"], check=True)
    import qrcode
    from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.ext import (
        Application, CommandHandler, CallbackQueryHandler,
        ContextTypes, ConversationHandler, MessageHandler, filters
    )

# ── Config ────────────────────────────────────────────────
BOT_TOKEN   = os.getenv("BOT_TOKEN", "")
ADMIN_IDS   = set(int(x.strip()) for x in os.getenv("ADMIN_IDS","").split(",") if x.strip().isdigit())
BOT_DIR     = Path("/opt/vpn-bot")
VPN_CFG     = BOT_DIR / "vpn_config.json"
CLIENTS_FILE= BOT_DIR / "clients.json"
XRAY_CFG    = Path("/usr/local/etc/xray/config.json")

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    handlers=[logging.StreamHandler(), logging.FileHandler(BOT_DIR/"bot.log")]
)
logger = logging.getLogger(__name__)

# ConversationHandler states
(ASK_NAME, ASK_LIMIT_GB, ASK_LIMIT_DAYS) = range(3)

# ── Data helpers ──────────────────────────────────────────
def vpn_cfg() -> dict:
    return json.loads(VPN_CFG.read_text()) if VPN_CFG.exists() else {}

def load_clients() -> list:
    if not CLIENTS_FILE.exists():
        return []
    return json.loads(CLIENTS_FILE.read_text()).get("clients", [])

def save_clients(clients: list):
    CLIENTS_FILE.write_text(json.dumps({"clients": clients}, indent=2, ensure_ascii=False))

def get_client(name: str) -> dict | None:
    return next((c for c in load_clients() if c["name"] == name), None)

def is_admin(uid: int) -> bool:
    return uid in ADMIN_IDS

def run(cmd: str) -> tuple[bool, str]:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return r.returncode == 0, (r.stdout.strip() or r.stderr.strip())
    except Exception as e:
        return False, str(e)

def fmt_bytes(b: int) -> str:
    if b >= 1_073_741_824: return f"{b/1_073_741_824:.2f} ГБ"
    if b >= 1_048_576:     return f"{b/1_048_576:.1f} МБ"
    if b >= 1024:          return f"{b/1024:.0f} КБ"
    return f"{b} Б"

# ── Xray config management ────────────────────────────────
def xray_config() -> dict:
    return json.loads(XRAY_CFG.read_text())

def save_xray_config(cfg: dict):
    XRAY_CFG.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    run("systemctl reload xray 2>/dev/null || systemctl restart xray")

def add_xray_client(user_uuid: str, email: str):
    cfg = xray_config()
    clients = cfg["inbounds"][0]["settings"]["clients"]
    clients.append({"id": user_uuid, "flow": "xtls-rprx-vision", "email": email})
    save_xray_config(cfg)

def remove_xray_client(user_uuid: str):
    cfg = xray_config()
    clients = cfg["inbounds"][0]["settings"]["clients"]
    cfg["inbounds"][0]["settings"]["clients"] = [
        c for c in clients if c.get("id") != user_uuid
    ]
    save_xray_config(cfg)

def get_xray_stats(email: str) -> tuple[int, int]:
    """Возвращает (uplink bytes, downlink bytes) для клиента"""
    ok_u, up = run(f"xray api stats --server=127.0.0.1:62789 -pattern 'user>>>{email}>>>traffic>>>uplink' 2>/dev/null | grep -oP '\"value\":\\s*\\K[0-9]+'")
    ok_d, dn = run(f"xray api stats --server=127.0.0.1:62789 -pattern 'user>>>{email}>>>traffic>>>downlink' 2>/dev/null | grep -oP '\"value\":\\s*\\K[0-9]+'")
    try:
        return int(up or 0), int(dn or 0)
    except:
        return 0, 0

def build_vless_link(user_uuid: str, name: str) -> str:
    c = vpn_cfg()
    sni = c.get("chosen_sni","")
    fp  = c.get("fingerprint","")
    params = f"encryption=none&flow=xtls-rprx-vision&security=reality&pbk={c['public_key']}&sid={c['short_id']}&type=tcp&headerType=none"
    if sni: params += f"&sni={sni}"
    if fp:  params += f"&fp={fp}"
    tag = name.replace(" ", "_")
    return f"vless://{user_uuid}@{c['public_ip']}:{c['port']}?{params}#{tag}"

def check_client_limits():
    """Проверяет и отключает клиентов с превышением лимитов"""
    clients = load_clients()
    changed = False
    for c in clients:
        if not c.get("active", True):
            continue
        # Лимит по времени
        if c.get("expires"):
            exp = datetime.fromisoformat(c["expires"])
            if datetime.now() > exp:
                c["active"] = False
                c["disabled_reason"] = "expired"
                remove_xray_client(c["uuid"])
                changed = True
                logger.info(f"Отключён {c['name']} — истёк срок")
                continue
        # Лимит по трафику
        if c.get("limit_gb"):
            up, dn = get_xray_stats(c["name"])
            total = up + dn
            c["used_bytes"] = total
            limit_bytes = c["limit_gb"] * 1_073_741_824
            if total >= limit_bytes:
                c["active"] = False
                c["disabled_reason"] = "traffic_exceeded"
                remove_xray_client(c["uuid"])
                changed = True
                logger.info(f"Отключён {c['name']} — превышен лимит трафика")
    if changed:
        save_clients(clients)

# ── Keyboards ─────────────────────────────────────────────
def main_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("👤 Клиенты", callback_data="clients_menu"),
         InlineKeyboardButton("📊 Статус", callback_data="status")],
        [InlineKeyboardButton("📡 Мой конфиг", callback_data="my_config"),
         InlineKeyboardButton("📲 Мой QR", callback_data="my_qr")],
        [InlineKeyboardButton("🔄 SNI ротация", callback_data="sni_menu"),
         InlineKeyboardButton("⚙️ Управление", callback_data="manage")],
        [InlineKeyboardButton("❓ Помощь", callback_data="help")],
    ])

def clients_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Добавить клиента", callback_data="add_client")],
        [InlineKeyboardButton("📋 Список клиентов", callback_data="list_clients")],
        [InlineKeyboardButton("🔙 Назад", callback_data="back_main")],
    ])

def manage_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔄 Перезапустить Xray", callback_data="restart_xray")],
        [InlineKeyboardButton("⏹ Стоп", callback_data="stop_xray"),
         InlineKeyboardButton("▶️ Старт", callback_data="start_xray")],
        [InlineKeyboardButton("📜 Логи", callback_data="logs")],
        [InlineKeyboardButton("🔙 Назад", callback_data="back_main")],
    ])

def back_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Главное меню", callback_data="back_main")]])

def client_action_kb(name: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📲 QR-код", callback_data=f"client_qr:{name}"),
         InlineKeyboardButton("🔗 Ссылка", callback_data=f"client_link:{name}")],
        [InlineKeyboardButton("📊 Трафик", callback_data=f"client_stats:{name}"),
         InlineKeyboardButton("🗑 Удалить", callback_data=f"client_del:{name}")],
        [InlineKeyboardButton("🔙 К списку", callback_data="list_clients")],
    ])

def sni_kb() -> InlineKeyboardMarkup:
    c = vpn_cfg()
    working = c.get("working_snis", [])
    btns = []
    for sni in working[:6]:
        btns.append([InlineKeyboardButton(f"🌐 {sni}", callback_data=f"set_sni:{sni}")])
    btns.append([InlineKeyboardButton("🚫 Пустой SNI", callback_data="set_sni:")])
    btns.append([InlineKeyboardButton("🔙 Назад", callback_data="back_main")])
    return InlineKeyboardMarkup(btns)

# ── Handlers ──────────────────────────────────────────────
async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_admin(user.id):
        await update.message.reply_text(
            f"⛔️ Нет доступа.\nВаш ID: `{user.id}`",
            parse_mode="Markdown"
        )
        return
    # Проверяем лимиты при каждом старте
    check_client_limits()
    c = vpn_cfg()
    await update.message.reply_text(
        f"👋 *Панель управления VPN*\n\n"
        f"📡 `{c.get('public_ip')}:{c.get('port')}`\n"
        f"🔐 VLESS + Reality\n"
        f"🌐 SNI: `{c.get('chosen_sni') or 'пустой'}`\n"
        f"👥 Клиентов: {len(load_clients())}",
        parse_mode="Markdown", reply_markup=main_kb()
    )

async def btn(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not is_admin(q.from_user.id):
        await q.edit_message_text("⛔️")
        return
    d = q.data
    c = vpn_cfg()

    if d == "back_main":
        check_client_limits()
        await q.edit_message_text(
            f"🏠 *Главное меню*\n👥 Клиентов: {len(load_clients())}",
            parse_mode="Markdown", reply_markup=main_kb()
        )

    # ── СТАТУС ──
    elif d == "status":
        ok, _ = run("systemctl is-active xray")
        _, ver = run("xray version 2>/dev/null | head -1")
        _, conns = run("ss -tnp | grep xray | wc -l")
        _, mem = run("ps aux | grep xray | grep -v grep | awk '{print $6}' | head -1")
        mem_mb = round(int(mem)/1024, 1) if (mem or "").isdigit() else "?"
        clients = load_clients()
        active = sum(1 for cl in clients if cl.get("active", True))

        # Трафик через API
        total_up = total_dn = 0
        for cl in clients:
            up, dn = get_xray_stats(cl["name"])
            total_up += up
            total_dn += dn

        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("🔄 Обновить", callback_data="status")],
            [InlineKeyboardButton("🔙 Назад", callback_data="back_main")]
        ])
        await q.edit_message_text(
            f"📊 *Статус сервера*\n\n"
            f"Xray: {'🟢 Работает' if ok else '🔴 Стоп'}\n"
            f"Версия: `{ver}`\n"
            f"Память: `{mem_mb} МБ`\n"
            f"Соединений: `{conns.strip()}`\n\n"
            f"👥 Клиентов: {active}/{len(clients)} активных\n"
            f"📶 Всего трафика:\n"
            f"  ↑ {fmt_bytes(total_up)}  ↓ {fmt_bytes(total_dn)}\n\n"
            f"_Обновлено: {datetime.now().strftime('%H:%M:%S')}_",
            parse_mode="Markdown", reply_markup=kb
        )

    # ── МОЙ КОНФИГ (для владельца) ──
    elif d == "my_config":
        link = build_vless_link(c.get("uuid",""), "My-VPN")
        await q.edit_message_text(
            f"📡 *Ваши данные*\n\n"
            f"IP: `{c.get('public_ip')}:{c.get('port')}`\n"
            f"UUID: `{c.get('uuid')}`\n"
            f"Public Key: `{c.get('public_key')}`\n"
            f"Short ID: `{c.get('short_id')}`\n"
            f"SNI: `{c.get('chosen_sni') or 'пустой'}`\n"
            f"FP: `{c.get('fingerprint') or 'default'}`\n\n"
            f"🔗 *Ссылка:*\n`{link}`",
            parse_mode="Markdown", reply_markup=back_kb()
        )

    elif d == "my_qr":
        link = build_vless_link(c.get("uuid",""), "My-VPN")
        await q.edit_message_text("⏳ Генерирую QR...")
        await send_qr(ctx, q.message.chat_id, link, "📲 *Ваш QR-код*\n\nОткройте Hiddify → + → Сканировать")

    # ── КЛИЕНТЫ МЕНЮ ──
    elif d == "clients_menu":
        await q.edit_message_text(
            "👤 *Управление клиентами*",
            parse_mode="Markdown", reply_markup=clients_kb()
        )

    elif d == "list_clients":
        clients = load_clients()
        if not clients:
            await q.edit_message_text(
                "👥 Клиентов пока нет.\nДобавьте первого!",
                reply_markup=clients_kb()
            )
            return
        btns = []
        for cl in clients:
            status = "🟢" if cl.get("active", True) else "🔴"
            label = f"{status} {cl['name']}"
            if cl.get("limit_gb"):
                up, dn = get_xray_stats(cl["name"])
                used_gb = (up + dn) / 1_073_741_824
                label += f" ({used_gb:.1f}/{cl['limit_gb']} ГБ)"
            elif cl.get("expires"):
                days_left = (datetime.fromisoformat(cl["expires"]) - datetime.now()).days
                label += f" ({max(0,days_left)} дн.)"
            btns.append([InlineKeyboardButton(label, callback_data=f"client_info:{cl['name']}")])
        btns.append([InlineKeyboardButton("➕ Добавить", callback_data="add_client")])
        btns.append([InlineKeyboardButton("🔙 Назад", callback_data="clients_menu")])
        await q.edit_message_text(
            f"👥 *Клиенты ({len(clients)}):*",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup(btns)
        )

    elif d.startswith("client_info:"):
        name = d.split(":", 1)[1]
        cl = get_client(name)
        if not cl:
            await q.edit_message_text("❌ Клиент не найден", reply_markup=back_kb())
            return
        up, dn = get_xray_stats(name)
        status = "🟢 Активен" if cl.get("active", True) else f"🔴 Отключён ({cl.get('disabled_reason','')})"
        info = f"👤 *{name}*\n\nСтатус: {status}\n"
        if cl.get("limit_gb"):
            pct = min(100, int((up+dn) / (cl['limit_gb'] * 1_073_741_824) * 100))
            bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
            info += f"Трафик: {fmt_bytes(up+dn)} / {cl['limit_gb']} ГБ\n`{bar}` {pct}%\n"
        if cl.get("expires"):
            days_left = (datetime.fromisoformat(cl["expires"]) - datetime.now()).days
            info += f"Истекает: {cl['expires'][:10]} (через {max(0,days_left)} дн.)\n"
        info += f"\nUUID: `{cl['uuid']}`"
        await q.edit_message_text(info, parse_mode="Markdown", reply_markup=client_action_kb(name))

    elif d.startswith("client_qr:"):
        name = d.split(":", 1)[1]
        cl = get_client(name)
        if not cl:
            await q.edit_message_text("❌ Не найден")
            return
        link = build_vless_link(cl["uuid"], name)
        await q.edit_message_text("⏳")
        await send_qr(ctx, q.message.chat_id, link, f"📲 QR для *{name}*")

    elif d.startswith("client_link:"):
        name = d.split(":", 1)[1]
        cl = get_client(name)
        if not cl:
            await q.edit_message_text("❌")
            return
        link = build_vless_link(cl["uuid"], name)
        await q.edit_message_text(
            f"🔗 *Ссылка для {name}:*\n\n`{link}`",
            parse_mode="Markdown", reply_markup=client_action_kb(name)
        )

    elif d.startswith("client_stats:"):
        name = d.split(":", 1)[1]
        cl = get_client(name)
        if not cl:
            await q.edit_message_text("❌")
            return
        up, dn = get_xray_stats(name)
        await q.edit_message_text(
            f"📊 *Трафик {name}:*\n\n"
            f"↑ Отправлено: {fmt_bytes(up)}\n"
            f"↓ Получено: {fmt_bytes(dn)}\n"
            f"Всего: {fmt_bytes(up+dn)}\n"
            f"{'Лимит: '+str(cl['limit_gb'])+' ГБ' if cl.get('limit_gb') else 'Без лимита'}",
            parse_mode="Markdown", reply_markup=client_action_kb(name)
        )

    elif d.startswith("client_del:"):
        name = d.split(":", 1)[1]
        cl = get_client(name)
        if cl:
            remove_xray_client(cl["uuid"])
            clients = [c for c in load_clients() if c["name"] != name]
            save_clients(clients)
        await q.edit_message_text(f"🗑 Клиент *{name}* удалён.", parse_mode="Markdown", reply_markup=clients_kb())

    # ── SNI РОТАЦИЯ ──
    elif d == "sni_menu":
        c = vpn_cfg()
        current = c.get("chosen_sni") or "пустой"
        await q.edit_message_text(
            f"🔄 *Ротация SNI*\n\n"
            f"Текущий: `{current}`\n\n"
            f"⚠️ Смена SNI перезапускает Xray.\n"
            f"Все клиенты переподключатся автоматически.\n\n"
            f"Выберите новый SNI:",
            parse_mode="Markdown", reply_markup=sni_kb()
        )

    elif d.startswith("set_sni:"):
        new_sni = d.split(":", 1)[1]
        await q.edit_message_text("⏳ Меняю SNI и перезапускаю Xray...")
        # Обновляем xray config
        xray_cfg = xray_config()
        rs = xray_cfg["inbounds"][0]["streamSettings"]["realitySettings"]
        if new_sni:
            rs["dest"] = f"{new_sni}:443"
            rs["serverNames"] = [new_sni]
        else:
            rs["dest"] = "www.microsoft.com:443"
            rs["serverNames"] = []
        save_xray_config(xray_cfg)
        # Обновляем vpn_config
        vpn = vpn_cfg()
        vpn["chosen_sni"] = new_sni
        vpn["dest"] = f"{new_sni}:443" if new_sni else "www.microsoft.com:443"
        VPN_CFG.write_text(json.dumps(vpn, indent=2))
        ok, _ = run("systemctl restart xray")
        status = "✅ Xray перезапущен" if ok else "❌ Ошибка перезапуска"
        await q.edit_message_text(
            f"🌐 SNI изменён на: `{new_sni or 'пустой'}`\n{status}\n\n"
            f"Обновите конфиг на устройствах!",
            parse_mode="Markdown", reply_markup=back_kb()
        )

    # ── УПРАВЛЕНИЕ XRAY ──
    elif d == "manage":
        ok, _ = run("systemctl is-active xray")
        await q.edit_message_text(
            f"⚙️ *Управление*\n\nXray: {'🟢 Работает' if ok else '🔴 Стоп'}",
            parse_mode="Markdown", reply_markup=manage_kb()
        )
    elif d == "restart_xray":
        await q.edit_message_text("⏳ Перезапуск...")
        ok, _ = run("systemctl restart xray")
        await q.edit_message_text(
            "✅ Xray перезапущен" if ok else "❌ Ошибка",
            reply_markup=manage_kb()
        )
    elif d == "stop_xray":
        run("systemctl stop xray")
        await q.edit_message_text("⏹ Xray остановлен", reply_markup=manage_kb())
    elif d == "start_xray":
        run("systemctl start xray")
        await q.edit_message_text("▶️ Xray запущен", reply_markup=manage_kb())
    elif d == "logs":
        _, logs = run("journalctl -u xray -n 25 --no-pager --output=short")
        await q.edit_message_text(
            f"📜 *Логи Xray:*\n\n```\n{logs[:3800]}\n```",
            parse_mode="Markdown", reply_markup=manage_kb()
        )

    # ── ПОМОЩЬ ──
    elif d == "help":
        await q.edit_message_text(
            "❓ *Помощь*\n\n"
            "*Добавить пользователя:*\n"
            "👤 Клиенты → ➕ Добавить → указать имя, лимит ГБ или дни\n\n"
            "*Выдать конфиг пользователю:*\n"
            "Список → имя клиента → 📲 QR или 🔗 Ссылка\n\n"
            "*Если VPN не работает:*\n"
            "1. 🔄 SNI ротация → попробуйте другой SNI\n"
            "2. ⚙️ Управление → Перезапустить\n"
            "3. 📜 Логи — посмотреть ошибки\n\n"
            "*Рекомендуемые клиенты:*\n"
            "• Android/iOS/ПК: Hiddify\n"
            "• Android: v2rayNG\n"
            "• iOS: Streisand\n"
            "• Windows: v2rayN",
            parse_mode="Markdown", reply_markup=back_kb()
        )

# ── Добавление клиента (ConversationHandler) ──────────────
async def add_client_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    await q.edit_message_text(
        "➕ *Новый клиент*\n\nВведите имя клиента (латиница, без пробелов):\n_Например: ivan_petrov_",
        parse_mode="Markdown"
    )
    return ASK_NAME

async def got_name(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    name = update.message.text.strip().replace(" ", "_")
    if get_client(name):
        await update.message.reply_text("❌ Клиент с таким именем уже есть. Введите другое:")
        return ASK_NAME
    ctx.user_data["new_client_name"] = name
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("∞ Без лимита", callback_data="limit_gb:0")],
        [InlineKeyboardButton("5 ГБ", callback_data="limit_gb:5"),
         InlineKeyboardButton("10 ГБ", callback_data="limit_gb:10")],
        [InlineKeyboardButton("30 ГБ", callback_data="limit_gb:30"),
         InlineKeyboardButton("100 ГБ", callback_data="limit_gb:100")],
        [InlineKeyboardButton("✏️ Своё значение", callback_data="limit_gb:custom")],
    ])
    await update.message.reply_text(
        f"👤 Клиент: *{name}*\n\nВыберите лимит трафика:",
        parse_mode="Markdown", reply_markup=kb
    )
    return ASK_LIMIT_GB

async def got_limit_gb_btn(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    val = q.data.split(":")[1]
    if val == "custom":
        await q.edit_message_text("Введите лимит в ГБ (только число, например 15):")
        return ASK_LIMIT_GB
    ctx.user_data["limit_gb"] = int(val)
    return await ask_days(q, ctx)

async def got_limit_gb_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    try:
        ctx.user_data["limit_gb"] = int(update.message.text.strip())
    except:
        await update.message.reply_text("❌ Введите число:")
        return ASK_LIMIT_GB
    return await ask_days_msg(update.message, ctx)

async def ask_days(q, ctx):
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("∞ Бессрочно", callback_data="limit_days:0")],
        [InlineKeyboardButton("7 дней", callback_data="limit_days:7"),
         InlineKeyboardButton("30 дней", callback_data="limit_days:30")],
        [InlineKeyboardButton("90 дней", callback_data="limit_days:90"),
         InlineKeyboardButton("365 дней", callback_data="limit_days:365")],
        [InlineKeyboardButton("✏️ Своё", callback_data="limit_days:custom")],
    ])
    gb = ctx.user_data.get("limit_gb", 0)
    await q.edit_message_text(
        f"Лимит трафика: *{'∞' if not gb else str(gb)+' ГБ'}*\n\nВыберите срок действия:",
        parse_mode="Markdown", reply_markup=kb
    )
    return ASK_LIMIT_DAYS

async def ask_days_msg(msg, ctx):
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("∞ Бессрочно", callback_data="limit_days:0")],
        [InlineKeyboardButton("7 дней", callback_data="limit_days:7"),
         InlineKeyboardButton("30 дней", callback_data="limit_days:30")],
        [InlineKeyboardButton("90 дней", callback_data="limit_days:90")],
    ])
    gb = ctx.user_data.get("limit_gb", 0)
    await msg.reply_text(
        f"Лимит трафика: *{'∞' if not gb else str(gb)+' ГБ'}*\n\nВыберите срок:",
        parse_mode="Markdown", reply_markup=kb
    )
    return ASK_LIMIT_DAYS

async def got_days_btn(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    val = q.data.split(":")[1]
    if val == "custom":
        await q.edit_message_text("Введите количество дней (только число):")
        return ASK_LIMIT_DAYS
    ctx.user_data["limit_days"] = int(val)
    return await create_client(q, ctx)

async def got_days_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    try:
        ctx.user_data["limit_days"] = int(update.message.text.strip())
    except:
        await update.message.reply_text("❌ Введите число:")
        return ASK_LIMIT_DAYS
    return await create_client_msg(update.message, ctx)

async def create_client(q, ctx):
    name     = ctx.user_data["new_client_name"]
    limit_gb = ctx.user_data.get("limit_gb", 0)
    limit_days = ctx.user_data.get("limit_days", 0)

    new_uuid = str(uuid.uuid4())
    expires  = None
    if limit_days:
        expires = (datetime.now() + timedelta(days=limit_days)).isoformat()

    client = {
        "name": name,
        "uuid": new_uuid,
        "active": True,
        "created": datetime.now().isoformat(),
        "limit_gb": limit_gb or None,
        "expires": expires,
        "used_bytes": 0
    }
    clients = load_clients()
    clients.append(client)
    save_clients(clients)
    add_xray_client(new_uuid, name)

    link = build_vless_link(new_uuid, name)
    info = (
        f"✅ *Клиент создан: {name}*\n\n"
        f"Лимит трафика: {'∞' if not limit_gb else str(limit_gb)+' ГБ'}\n"
        f"Срок: {'∞' if not expires else expires[:10]}\n\n"
        f"🔗 Ссылка:\n`{link}`\n\n"
        f"_QR-код — в меню клиента_"
    )
    await q.edit_message_text(info, parse_mode="Markdown", reply_markup=clients_kb())
    ctx.user_data.clear()
    return ConversationHandler.END

async def create_client_msg(msg, ctx):
    name     = ctx.user_data["new_client_name"]
    limit_gb = ctx.user_data.get("limit_gb", 0)
    limit_days = ctx.user_data.get("limit_days", 0)

    new_uuid = str(uuid.uuid4())
    expires  = None
    if limit_days:
        expires = (datetime.now() + timedelta(days=limit_days)).isoformat()

    client = {
        "name": name, "uuid": new_uuid, "active": True,
        "created": datetime.now().isoformat(),
        "limit_gb": limit_gb or None, "expires": expires, "used_bytes": 0
    }
    clients = load_clients()
    clients.append(client)
    save_clients(clients)
    add_xray_client(new_uuid, name)

    link = build_vless_link(new_uuid, name)
    await msg.reply_text(
        f"✅ *{name}* создан!\n"
        f"Лимит: {'∞' if not limit_gb else str(limit_gb)+' ГБ'}\n"
        f"Срок: {'∞' if not expires else expires[:10]}\n\n"
        f"`{link}`",
        parse_mode="Markdown", reply_markup=main_kb()
    )
    ctx.user_data.clear()
    return ConversationHandler.END

async def cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data.clear()
    await update.message.reply_text("Отменено.", reply_markup=main_kb())
    return ConversationHandler.END

# ── QR helper ─────────────────────────────────────────────
async def send_qr(ctx, chat_id: int, link: str, caption: str):
    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(link)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    buf.name = "vpn.png"
    await ctx.bot.send_photo(chat_id=chat_id, photo=buf,
                              caption=caption, parse_mode="Markdown")
    await ctx.bot.send_message(chat_id=chat_id, text="🏠", reply_markup=main_kb())

async def unknown(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if is_admin(update.effective_user.id):
        await update.message.reply_text("/start — открыть панель")

# ── Main ──────────────────────────────────────────────────
def main():
    if not BOT_TOKEN:
        logger.error("BOT_TOKEN не установлен!")
        sys.exit(1)

    app = Application.builder().token(BOT_TOKEN).build()

    # ConversationHandler для добавления клиента
    conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(add_client_start, pattern="^add_client$")],
        states={
            ASK_NAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, got_name)],
            ASK_LIMIT_GB: [
                CallbackQueryHandler(got_limit_gb_btn, pattern="^limit_gb:"),
                MessageHandler(filters.TEXT & ~filters.COMMAND, got_limit_gb_text),
            ],
            ASK_LIMIT_DAYS: [
                CallbackQueryHandler(got_days_btn, pattern="^limit_days:"),
                MessageHandler(filters.TEXT & ~filters.COMMAND, got_days_text),
            ],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
        per_message=False,
    )

    app.add_handler(CommandHandler("start", start))
    app.add_handler(conv)
    app.add_handler(CallbackQueryHandler(btn))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, unknown))

    logger.info(f"Бот запущен. Admins: {ADMIN_IDS}")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
