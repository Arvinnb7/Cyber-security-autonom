"use client";

import { createContext, useContext, useEffect, useState } from "react";

export type Lang = "en" | "fa";

const STORAGE_KEY = "sentinel_lang";

// Persian names for the 10 catalog detections (keyed by det_id).
export const DET_NAMES: Record<string, { en: string; fa: string }> = {
  "DET-001": { en: "Suspicious Login", fa: "ورود مشکوک" },
  "DET-002": { en: "Account Compromise", fa: "سرقت حساب کاربری" },
  "DET-003": { en: "Phishing Attack", fa: "حمله فیشینگ" },
  "DET-004": { en: "Malware Execution", fa: "اجرای فایل مخرب" },
  "DET-005": { en: "Ransomware Behavior", fa: "رفتار باج‌افزاری" },
  "DET-006": { en: "Data Exfiltration", fa: "خروج غیرمجاز اطلاعات" },
  "DET-007": { en: "Privilege Abuse", fa: "سوءاستفاده از دسترسی" },
  "DET-008": { en: "Security Configuration Changes", fa: "تغییرات مشکوک امنیتی" },
  "DET-009": { en: "Lateral Movement", fa: "حرکت جانبی مهاجم" },
  "DET-010": { en: "Privilege Escalation", fa: "ارتقای سطح دسترسی" },
};

const DICT: Record<string, { en: string; fa: string }> = {
  // brand / nav
  "brand.tag": { en: "Autonomous SOC", fa: "SOC خودمختار" },
  "nav.dashboard": { en: "Dashboard", fa: "داشبورد" },
  "nav.incidents": { en: "Incidents", fa: "رخدادها" },
  "nav.detections": { en: "Detection Catalog", fa: "کاتالوگ تشخیص" },
  "nav.users": { en: "Users & Assets", fa: "کاربران و دارایی‌ها" },
  "nav.chat": { en: "Security Assistant", fa: "دستیار امنیتی" },
  "nav.integrations": { en: "Integrations", fa: "اتصال‌ها" },
  "nav.reports": { en: "Weekly Reports", fa: "گزارش‌های هفتگی" },
  "nav.team": { en: "Team & Access", fa: "تیم و دسترسی" },
  "nav.alerts": { en: "Alerting", fa: "اعلان‌ها" },

  // roles
  "role.admin": { en: "admin", fa: "مدیر" },
  "role.analyst": { en: "analyst", fa: "تحلیلگر" },
  "role.viewer": { en: "viewer", fa: "بیننده" },

  // team / accounts management
  "team.subtitle": {
    en: "Manage who can access Sentinel and what they can do",
    fa: "مدیریت اینکه چه کسی به Sentinel دسترسی دارد و چه کاری می‌تواند بکند",
  },
  "team.add": { en: "＋ Add user", fa: "＋ افزودن کاربر" },
  "team.username": { en: "Username", fa: "نام کاربری" },
  "team.password": { en: "Password", fa: "رمز عبور" },
  "team.email": { en: "Email", fa: "ایمیل" },
  "team.role": { en: "Role", fa: "نقش" },
  "team.status": { en: "Status", fa: "وضعیت" },
  "team.lastLogin": { en: "Last login", fa: "آخرین ورود" },
  "team.active": { en: "active", fa: "فعال" },
  "team.inactive": { en: "inactive", fa: "غیرفعال" },
  "team.enable": { en: "Enable", fa: "فعال‌کردن" },
  "team.disable": { en: "Disable", fa: "غیرفعال‌کردن" },
  "team.delete": { en: "Delete", fa: "حذف" },
  "team.resetPw": { en: "Reset password", fa: "ریست رمز" },
  "team.save": { en: "Create user", fa: "ساخت کاربر" },
  "team.saving": { en: "Saving…", fa: "در حال ذخیره…" },
  "team.cancel": { en: "Cancel", fa: "انصراف" },
  "team.never": { en: "never", fa: "هرگز" },
  "team.you": { en: "you", fa: "شما" },
  "team.roleAdminDesc": { en: "Full control", fa: "کنترل کامل" },
  "team.roleAnalystDesc": { en: "Triage & respond", fa: "تریاژ و واکنش" },
  "team.roleViewerDesc": { en: "Read-only", fa: "فقط خواندن" },

  // integrations
  "int.subtitle": {
    en: "Connect your organization's security sources by entering their API credentials",
    fa: "سرویس‌های امنیتی سازمانت را با وارد کردن credentialهای API متصل کن",
  },
  "int.add": { en: "＋ Add connection", fa: "＋ افزودن اتصال" },
  "int.none": { en: "No connections yet. Add your first source.", fa: "هنوز اتصالی نیست. اولین سرویس را اضافه کن." },
  "int.provider": { en: "Provider", fa: "سرویس" },
  "int.displayName": { en: "Display name", fa: "نام نمایشی" },
  "int.save": { en: "Save connection", fa: "ذخیره اتصال" },
  "int.saving": { en: "Saving…", fa: "در حال ذخیره…" },
  "int.cancel": { en: "Cancel", fa: "انصراف" },
  "int.test": { en: "Test", fa: "تست" },
  "int.testing": { en: "Testing…", fa: "در حال تست…" },
  "int.enable": { en: "Enable", fa: "فعال‌سازی" },
  "int.disable": { en: "Disable", fa: "غیرفعال‌سازی" },
  "int.delete": { en: "Delete", fa: "حذف" },
  "int.enabled": { en: "enabled", fa: "فعال" },
  "int.disabled": { en: "disabled", fa: "غیرفعال" },
  "int.lastSync": { en: "last sync", fa: "آخرین همگام‌سازی" },
  "int.live": { en: "live connector", fa: "کانکتور زنده" },
  "int.pending": { en: "connector pending", fa: "کانکتور در دست ساخت" },
  "int.secretSet": { en: "set", fa: "تنظیم‌شده" },
  "int.leaveBlank": { en: "leave blank to keep current", fa: "برای حفظ مقدار فعلی خالی بگذار" },
  "int.statusConnected": { en: "connected", fa: "متصل" },
  "int.statusError": { en: "error", fa: "خطا" },
  "int.statusUnknown": { en: "not tested", fa: "تست‌نشده" },
  "nav.signout": { en: "Sign out", fa: "خروج" },
  "lang.toggle": { en: "فارسی", fa: "English" },
  "mode.demo": { en: "Demo data", fa: "داده‌ی دمو" },
  "mode.live": { en: "Live data", fa: "داده‌ی واقعی" },
  "mode.switching": { en: "Switching…", fa: "در حال تغییر…" },
  "mode.toLive": { en: "Switch to Live", fa: "تغییر به واقعی" },
  "mode.toDemo": { en: "Switch to Demo", fa: "تغییر به دمو" },

  // login
  "login.subtitle": { en: "Autonomous Security Operations", fa: "عملیات امنیتی خودمختار" },
  "login.username": { en: "Username", fa: "نام کاربری" },
  "login.password": { en: "Password", fa: "رمز عبور" },
  "login.signin": { en: "Sign in", fa: "ورود" },
  "login.signingin": { en: "Signing in…", fa: "در حال ورود…" },
  "login.invalid": { en: "Invalid credentials", fa: "اطلاعات ورود نادرست است" },
  "login.demo": { en: "Demo credentials: admin / admin", fa: "اطلاعات دمو: admin / admin" },

  // dashboard
  "dash.title": { en: "Organization Risk", fa: "ریسک سازمان" },
  "dash.subtitle": {
    en: "Autonomous monitoring across 8 connected security sources · live",
    fa: "مانیتورینگ خودمختار روی ۸ منبع امنیتی متصل · زنده",
  },
  "dash.simulate": { en: "⚡ Simulate attack", fa: "⚡ شبیه‌سازی حمله" },
  "dash.simulating": { en: "Simulating…", fa: "در حال شبیه‌سازی…" },
  "dash.overall": { en: "Overall risk score", fa: "امتیاز کلی ریسک" },
  "dash.activeIncidents": { en: "Active incidents", fa: "رخدادهای فعال" },
  "dash.eventsIngested": { en: "Events ingested", fa: "رویدادهای جمع‌آوری‌شده" },
  "dash.bySeverity": { en: "Detections by severity", fa: "تشخیص‌ها بر اساس شدت" },
  "dash.activeThreats": { en: "Active threats", fa: "تهدیدهای فعال" },
  "dash.noThreats": { en: "No active threats.", fa: "تهدید فعالی وجود ندارد." },
  "dash.activeCount": { en: "active incident(s)", fa: "رخداد فعال" },
  "dash.totalIncidents": { en: "Total incidents", fa: "کل رخدادها" },
  "dash.resolved": { en: "Resolved", fa: "حل‌شده" },
  "dash.pendingActions": { en: "Pending actions", fa: "اقدامات در انتظار" },
  "dash.riskyUsers": { en: "High-risk users", fa: "کاربران پرخطر" },
  "dash.riskySystems": { en: "High-risk systems", fa: "سیستم‌های پرخطر" },
  "dash.topIncidents": { en: "Top incidents", fa: "مهم‌ترین رخدادها" },
  "common.confidence": { en: "confidence", fa: "اطمینان" },
  "common.blocked": { en: "blocked", fa: "مسدود" },
  "common.sensitivity": { en: "sensitivity", fa: "حساسیت" },
  "common.target": { en: "target", fa: "هدف" },
  "common.via": { en: "via", fa: "از طریق" },
  "common.actor": { en: "actor", fa: "عامل" },
  "common.none": { en: "None", fa: "هیچ" },

  // incidents
  "inc.title": { en: "Incidents", fa: "رخدادها" },
  "inc.subtitle": {
    en: "Correlated, scored and explained automatically — newest and riskiest first",
    fa: "به‌صورت خودکار همبسته، امتیازدهی و تشریح شده — جدیدترین و پرخطرترین اول",
  },
  "inc.empty": { en: "No incidents for this filter.", fa: "رخدادی برای این فیلتر وجود ندارد." },
  "filter.all": { en: "all", fa: "همه" },
  "filter.open": { en: "open", fa: "باز" },
  "filter.investigating": { en: "investigating", fa: "در حال بررسی" },
  "filter.resolved": { en: "resolved", fa: "حل‌شده" },
  "filter.dismissed": { en: "dismissed", fa: "رد‌شده" },

  // incident detail
  "det.detected": { en: "detected", fa: "شناسایی‌شده" },
  "det.back": { en: "← Back", fa: "بازگشت →" },
  "det.assessment": { en: "Analyst assessment", fa: "ارزیابی تحلیلگر" },
  "det.likely": { en: "likely", fa: "احتمال" },
  "det.execSummary": { en: "Executive summary", fa: "خلاصه مدیریتی" },
  "sum.what": { en: "What happened", fa: "چه اتفاقی افتاد" },
  "sum.why": { en: "Why it matters", fa: "چرا مهم است" },
  "sum.evidence": { en: "Supporting evidence", fa: "شواهد پشتیبان" },
  "sum.damage": { en: "Potential damage", fa: "خسارت احتمالی" },
  "sum.action": { en: "Recommended action", fa: "اقدام پیشنهادی" },
  "sum.approval": { en: "Human approval", fa: "تأیید انسانی" },
  "det.evidenceFactors": { en: "Evidence & matched factors", fa: "شواهد و فاکتورهای منطبق" },
  "det.requiredEvidence": { en: "Required evidence", fa: "شواهد لازم" },
  "det.scoringFactors": { en: "Scoring factors (→ threat score)", fa: "فاکتورهای امتیازی (← امتیاز تهدید)" },
  "det.timeline": { en: "Attack timeline", fa: "خط زمانی حمله" },
  "det.riskScores": { en: "Risk scores", fa: "امتیازهای ریسک" },
  "score.threat": { en: "Threat severity", fa: "شدت تهدید" },
  "score.user": { en: "User risk", fa: "ریسک کاربر" },
  "score.asset": { en: "Asset risk", fa: "ریسک دارایی" },
  "score.business": { en: "Business impact", fa: "خسارت کسب‌وکار" },
  "score.final": { en: "FINAL SCORE", fa: "امتیاز نهایی" },
  "det.response": { en: "Response (needs approval)", fa: "واکنش (نیازمند تأیید)" },
  "det.audit": { en: "Audit trail", fa: "سابقه ممیزی" },
  "det.triage": { en: "Triage", fa: "تریاژ" },
  "triage.investigating": { en: "Investigating", fa: "در حال بررسی" },
  "triage.resolve": { en: "Resolve", fa: "حل کن" },
  "triage.dismiss": { en: "Dismiss", fa: "رد کن" },
  "det.currentStatus": { en: "Current status:", fa: "وضعیت فعلی:" },
  "det.confirm": { en: "Confirm:", fa: "تأیید:" },
  "det.confirmBody": {
    en: "This response action requires manager approval before it is executed.",
    fa: "این اقدام واکنشی پیش از اجرا نیازمند تأیید مدیر است.",
  },
  "det.targetField": { en: "Target", fa: "هدف" },
  "det.cancel": { en: "Cancel", fa: "انصراف" },
  "det.approveExecute": { en: "Approve & execute", fa: "تأیید و اجرا" },
  "det.executing": { en: "Executing…", fa: "در حال اجرا…" },

  // action labels (by action type)
  "action.block_user": { en: "Block User", fa: "مسدودسازی کاربر" },
  "action.reset_password": { en: "Reset Password", fa: "ریست رمز عبور" },
  "action.kill_session": { en: "Kill Session", fa: "بستن نشست" },
  "action.block_ip": { en: "Block IP", fa: "مسدودسازی IP" },

  // users page
  "users.subtitle": {
    en: "Identity and asset risk, continuously recomputed from incidents",
    fa: "ریسک هویت و دارایی، به‌صورت پیوسته از رخدادها محاسبه می‌شود",
  },
  "users.users": { en: "Users", fa: "کاربران" },
  "users.assets": { en: "Assets", fa: "دارایی‌ها" },
  "users.privileged": { en: "privileged", fa: "دسترسی ویژه" },

  // chat
  "chat.subtitle": {
    en: "Ask questions in plain language — answers come from live data",
    fa: "به زبان ساده بپرس — پاسخ‌ها از دیتای زنده می‌آیند",
  },
  "chat.greeting": {
    en: "Hi — I'm Sentinel. Ask me anything about your security posture.",
    fa: "سلام — من Sentinel هستم. هر سؤالی درباره‌ی وضعیت امنیتی‌ات بپرس.",
  },
  "chat.placeholder": { en: "Ask about incidents, users, threats…", fa: "درباره رخدادها، کاربران، تهدیدها بپرس…" },
  "chat.send": { en: "Send", fa: "ارسال" },
  "chat.thinking": { en: "Sentinel is thinking…", fa: "Sentinel در حال فکر کردن…" },
  "chat.error": { en: "Sorry, something went wrong.", fa: "متأسفم، مشکلی پیش آمد." },
  "chat.s1": { en: "Show today's most dangerous incidents", fa: "خطرناک‌ترین رخدادهای امروز را نشان بده" },
  "chat.s2": { en: "Which users are the riskiest?", fa: "کدام کاربرها بیشترین ریسک را دارند؟" },
  "chat.s3": { en: "What are the active threats right now?", fa: "تهدیدهای فعال در حال حاضر چیست؟" },
  "chat.s4": { en: "Which systems are most at risk?", fa: "کدام سیستم‌ها بیشترین ریسک را دارند؟" },

  // reports
  "reports.subtitle": {
    en: "Auto-generated executive summaries: what happened, what's resolved, what needs action",
    fa: "خلاصه‌های مدیریتیِ خودکار: چه شد، چه حل شد، چه چیزی نیاز به اقدام دارد",
  },
  "reports.generate": { en: "＋ Generate now", fa: "＋ همین حالا بساز" },
  "reports.generating": { en: "Generating…", fa: "در حال ساخت…" },
  "reports.history": { en: "History", fa: "تاریخچه" },
  "reports.empty": { en: "No reports yet. Generate one.", fa: "هنوز گزارشی ساخته نشده. یکی بساز." },
  "reports.incidents": { en: "incidents", fa: "رخداد" },
  "reports.select": { en: "Select or generate a report.", fa: "یک گزارش انتخاب یا بساز." },

  // detections page
  "cat.subtitle": {
    en: "The MVP source of truth — 10 detections, their scoring factors and approval policy",
    fa: "منبع حقیقتِ MVP — ۱۰ تشخیص، فاکتورهای امتیازی و سیاست تأیید آن‌ها",
  },
  "cat.scoringFactors": { en: "Scoring factors", fa: "فاکتورهای امتیازی" },
  "cat.signals": { en: "Detection signals", fa: "سیگنال‌های تشخیص" },
  "cat.dataSources": { en: "Required data sources", fa: "منابع داده لازم" },
  "cat.response": { en: "Recommended response", fa: "واکنش پیشنهادی" },

  // badges
  "badge.claude": { en: "✦ Claude analysis", fa: "✦ تحلیل Claude" },
  "badge.rulebased": { en: "rule-based summary", fa: "خلاصه‌ی مبتنی بر قاعده" },
  "badge.rulebasedShort": { en: "rule-based", fa: "مبتنی بر قاعده" },
  "badge.approval": { en: "approval", fa: "تأیید" },

  // severity / status / band labels
  "sev.critical": { en: "critical", fa: "بحرانی" },
  "sev.high": { en: "high", fa: "بالا" },
  "sev.medium": { en: "medium", fa: "متوسط" },
  "sev.low": { en: "low", fa: "پایین" },
  "band.Critical": { en: "Critical", fa: "بحرانی" },
  "band.High": { en: "High", fa: "بالا" },
  "band.Medium": { en: "Medium", fa: "متوسط" },
  "band.Low": { en: "Low", fa: "پایین" },
  "status.open": { en: "open", fa: "باز" },
  "status.investigating": { en: "investigating", fa: "در حال بررسی" },
  "status.resolved": { en: "resolved", fa: "حل‌شده" },
  "status.dismissed": { en: "dismissed", fa: "رد‌شده" },
  "status.pending": { en: "pending", fa: "در انتظار" },
  "status.executed": { en: "executed", fa: "اجرا‌شده" },
  "status.rejected": { en: "rejected", fa: "رد‌شده" },
  "status.blocked": { en: "blocked", fa: "مسدود (سیاست)" },
  "status.failed": { en: "failed", fa: "ناموفق" },

  // automated response (integrations)
  "int.response": { en: "Automated response", fa: "واکنش خودکار" },
  "int.responseOn": { en: "actions enabled", fa: "اکشن‌ها فعال" },
  "int.responseOff": { en: "actions disabled", fa: "اکشن‌ها غیرفعال" },
  "int.enableActions": { en: "Enable actions", fa: "فعال‌کردن اکشن‌ها" },
  "int.disableActions": { en: "Disable actions", fa: "غیرفعال‌کردن اکشن‌ها" },
  "int.responseHint": {
    en: "When on, approved response actions really execute against this source.",
    fa: "وقتی روشن باشد، اکشن‌های تأییدشده واقعاً روی این سرویس اجرا می‌شوند.",
  },

  // alerting / notification channels
  "alerts.subtitle": {
    en: "Deliver security alerts to your team — email, Teams or Slack — when incidents fire or an action needs approval",
    fa: "اعلان‌های امنیتی را به تیمت برسان — ایمیل، Teams یا Slack — وقتی رخداد رخ می‌دهد یا اقدامی نیاز به تأیید دارد",
  },
  "alerts.add": { en: "＋ Add channel", fa: "＋ افزودن کانال" },
  "alerts.none": {
    en: "No channels yet. Add one so your team gets alerted.",
    fa: "هنوز کانالی نیست. یکی اضافه کن تا تیمت خبردار شود.",
  },
  "alerts.kind": { en: "Channel type", fa: "نوع کانال" },
  "alerts.displayName": { en: "Display name", fa: "نام نمایشی" },
  "alerts.minSeverity": { en: "Minimum severity", fa: "حداقل شدت" },
  "alerts.minSeverityHint": {
    en: "Only alert this channel for incidents at or above this severity.",
    fa: "فقط برای رخدادهای هم‌سطح یا شدیدتر از این، به این کانال اعلان بده.",
  },
  "alerts.onIncident": { en: "On new incidents", fa: "هنگام رخداد جدید" },
  "alerts.onApproval": { en: "On approval requests", fa: "هنگام درخواست تأیید" },
  "alerts.save": { en: "Save channel", fa: "ذخیره کانال" },
  "alerts.saving": { en: "Saving…", fa: "در حال ذخیره…" },
  "alerts.cancel": { en: "Cancel", fa: "انصراف" },
  "alerts.test": { en: "Send test", fa: "ارسال تست" },
  "alerts.testing": { en: "Sending…", fa: "در حال ارسال…" },
  "alerts.enable": { en: "Enable", fa: "فعال‌سازی" },
  "alerts.disable": { en: "Disable", fa: "غیرفعال‌سازی" },
  "alerts.delete": { en: "Delete", fa: "حذف" },
  "alerts.enabled": { en: "enabled", fa: "فعال" },
  "alerts.disabled": { en: "disabled", fa: "غیرفعال" },
  "alerts.secretSet": { en: "set", fa: "تنظیم‌شده" },
  "alerts.lastSent": { en: "last sent", fa: "آخرین ارسال" },
  "alerts.recent": { en: "Recent deliveries", fa: "ارسال‌های اخیر" },
  "alerts.recentEmpty": { en: "No alerts sent yet.", fa: "هنوز اعلانی ارسال نشده." },
  "alerts.statusConnected": { en: "healthy", fa: "سالم" },
  "alerts.statusError": { en: "error", fa: "خطا" },
  "alerts.statusUnknown": { en: "not tested", fa: "تست‌نشده" },
  "alerts.onHealth": { en: "On platform health issues", fa: "هنگام مشکلِ سلامتِ سامانه" },

  // platform self-monitoring
  "health.degraded": {
    en: "Sentinel is not fully monitoring your environment",
    fa: "Sentinel در حال حاضر محیط شما را کامل مانیتور نمی‌کند",
  },
  "health.warning": {
    en: "While this is unresolved, an empty incident list does NOT mean you are safe.",
    fa: "تا وقتی این مشکل حل نشده، خالی‌بودن فهرست رخدادها به معنی امن‌بودن نیست.",
  },

  // SLA / operations metrics
  "sla.title": { en: "Response performance", fa: "کارایی پاسخ‌دهی" },
  "sla.window": { en: "last 30 days", fa: "۳۰ روز اخیر" },
  "sla.mtta": { en: "Mean time to acknowledge", fa: "میانگین زمان تا رسیدگی" },
  "sla.mttr": { en: "Mean time to resolve", fa: "میانگین زمان تا حل" },
  "sla.autonomous": { en: "Handled autonomously", fa: "پردازش‌شده به‌صورت خودکار" },
  "sla.fpRate": { en: "False-positive rate", fa: "نرخ هشدار اشتباه" },

  // casework
  "case.assignee": { en: "Assigned to", fa: "واگذارشده به" },
  "case.unassigned": { en: "unassigned", fa: "واگذارنشده" },
  "case.assign": { en: "Assign", fa: "واگذاری" },
  "case.acknowledge": { en: "Acknowledge", fa: "رسیدگی می‌کنم" },
  "case.acknowledged": { en: "Acknowledged by", fa: "رسیدگی‌شده توسط" },
  "case.notes": { en: "Case notes", fa: "یادداشت‌های پرونده" },
  "case.notePlaceholder": { en: "Add a note for the record…", fa: "یادداشتی برای سابقه بنویس…" },
  "case.addNote": { en: "Add note", fa: "افزودن یادداشت" },
  "case.noNotes": { en: "No notes yet.", fa: "هنوز یادداشتی نیست." },
  "case.closeReason": { en: "Closing reason", fa: "دلیل بستن" },
  "case.true_positive": { en: "True positive", fa: "تهدید واقعی" },
  "case.false_positive": { en: "False positive", fa: "هشدار اشتباه" },
  "case.benign": { en: "Benign / expected", fa: "بی‌خطر / مورد انتظار" },
  "case.sensitivity": { en: "Business sensitivity", fa: "حساسیت کسب‌وکار" },
  "case.privileged": { en: "Privileged account", fa: "حساب دارای دسترسی ویژه" },
  "case.save": { en: "Save", fa: "ذخیره" },
};

type Ctx = { lang: Lang; dir: "rtl" | "ltr"; setLang: (l: Lang) => void; t: (key: string) => string };
const LanguageContext = createContext<Ctx | null>(null);

export function LanguageProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = useState<Lang>("en");

  useEffect(() => {
    const saved = (typeof window !== "undefined" && window.localStorage.getItem(STORAGE_KEY)) as Lang | null;
    if (saved === "fa" || saved === "en") setLangState(saved);
  }, []);

  useEffect(() => {
    const dir = lang === "fa" ? "rtl" : "ltr";
    document.documentElement.lang = lang;
    document.documentElement.dir = dir;
  }, [lang]);

  const setLang = (l: Lang) => {
    window.localStorage.setItem(STORAGE_KEY, l);
    setLangState(l);
  };

  const t = (key: string) => DICT[key]?.[lang] ?? key;
  const dir = lang === "fa" ? "rtl" : "ltr";

  return <LanguageContext.Provider value={{ lang, dir, setLang, t }}>{children}</LanguageContext.Provider>;
}

export function useLang(): Ctx {
  const ctx = useContext(LanguageContext);
  if (!ctx) throw new Error("useLang must be used within LanguageProvider");
  return ctx;
}

/** Localized detection/threat name from a det_id (falls back to English/threat_type). */
export function detName(detId: string, lang: Lang, fallback = ""): string {
  const entry = DET_NAMES[detId];
  if (!entry) return fallback;
  return lang === "fa" ? entry.fa : entry.en;
}
