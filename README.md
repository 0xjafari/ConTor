# 🔌 ConTor — Connect Tor + DNS Scanner + Local DNS Proxy / اتصال به تور + اسکنر DNS + پروکسی DNS محلی

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)
[![Tor](https://img.shields.io/badge/Tor-Integrated-purple.svg)](https://www.torproject.org/)
[![DNS](https://img.shields.io/badge/DNS-Scanner%20%7C%20Proxy-brightgreen.svg)]()

> **English** – All‑in‑one toolkit: Run Tor, scan for open DNS servers (UDP/TCP/DoT/DoH), and launch a local DNS proxy — all from a beautiful GUI.  
> **فارسی** – یک ابزار همه‌کاره برای اجرای تور، اسکن سرورهای DNS باز (UDP/TCP/DoT/DoH) و راه‌اندازی پروکسی DNS محلی، همه در یک رابط گرافیکی زیبا.

- 🔐 **Tor Control** – Start/Stop, renew identity, view circuits, monitor bandwidth  
- 🌐 **DNS Scanner** – Scan CIDR ranges, detect fake DNS (hijacking), find DoH/DoT servers  
- 🚀 **DNS Proxy** – Forward queries to custom upstreams (your scanned results) with caching  
- 🎨 **Ultra UI** – Neon design, animations, real-time clock & bandwidth, right‑click menus  

---

## 📖 Table of Contents / فهرست مطالب

1. [Architecture Overview](#-1-architecture-overview--معماری-کلی)
2. [Tor Integration](#-2-tor-integration--اتصال-به-تور)
3. [DNS Scanner](#-3-dns-scanner--اسکنر-dns)
4. [DNS Proxy](#-4-dns-proxy--پروکسی-dns)
5. [Threat Model](#-5-threat-model--مدل-تهدید)
6. [Comparison with Similar Tools](#-6-comparison-with-similar-tools--مقایسه-با-ابزارهای-مشابه)
7. [Project Structure](#-7-project-structure--ساختار-پروژه)
8. [Installation & Usage](#-8-installation--usage--نصب-و-استفاده)
9. [Logging & Privacy](#-9-logging--privacy--لاگ‌ها-و-حریم-خصوصی)
10. [Limitations & Future Work](#-10-limitations--future-work--محدودیت‌ها-و-کارهای-آتی)
11. [Security Recommendations](#-11-security-recommendations--توصیه‌های-امنیتی)
12. [Target Audience & Intended Use](#-12-target-audience--intended-use--کاربران-هدف-و-کاربرد-مجاز)
13. [Prohibited Use & Disclaimer](#-13-prohibited-use--disclaimer--کاربری-ممنوع-و-سلب-مسئولیت)
14. [License (GNU GPLv3)](#-14-license-gnu-gplv3--مجوز-gnu-gplv3)

---

# 🧠 1. Architecture Overview / معماری کلی

**English**  
ConTor is a **Python 3 desktop application** built with `tkinter`. It integrates three independent modules:

| Module | Purpose | Key Technologies |
|--------|---------|------------------|
| **Tor Controller** | Spawn and manage Tor daemon | `subprocess`, `stem` (control port) |
| **DNS Scanner** | Probe IP ranges for open DNS resolvers | Raw UDP/TCP sockets, SSL, `concurrent.futures` |
| **DNS Proxy** | Local caching forwarder | UDP server, in‑memory cache |

All configuration is stored in a single JSON file (`tor_dns_config.json`). No external database is required.

**فارسی**  
ConTor یک برنامه دسکتاپ پایتون ۳ با رابط گرافیکی `tkinter` است. سه ماژول مستقل را یکپارچه می‌کند:

| ماژول | هدف | فناوری‌های کلیدی |
|-------|------|------------------|
| **کنترلر تور** | اجرا و مدیریت فرآیند Tor | `subprocess`، `stem` (پورت کنترل) |
| **اسکنر DNS** | جستجوی رزلورهای DNS باز در محدوده IP | سوکت‌های UDP/TCP خام، SSL، `concurrent.futures` |
| **پروکسی DNS** | ارسال‌کننده محلی با کش | سرور UDP، کش درون‌حافظه |

تمام تنظیمات در یک فایل JSON به نام `tor_dns_config.json` ذخیره می‌شود. هیچ پایگاه داده خارجی نیاز نیست.

---

# 🔐 2. Tor Integration / اتصال به تور

**English**  

```
ConTor GUI
   │
   ├─► starts tor.exe (or tor binary) with custom torrc
   │
   ├─► connects to ControlPort (default 9051) via stem
   │      └─► NEWNYM signal, circuit info, traffic stats
   │
   └─► SOCKS5 proxy exposed on 127.0.0.1:9050 (for browsers/apps)
```

- **ControlPort** (9051) – used *only* for internal commands.  
- **SOCKS5** (9050) – what you configure in Firefox, cURL, etc.

**Supported Authentication** – None (default), password, or cookie file.

**Bridges & Obfs4** – You can paste bridge lines (including `obfs4`) into the GUI.  
ConTor automatically adds `UseBridges 1` and `ClientTransportPlugin` lines to `torrc`.

**فارسی**  

```
ConTor GUI
   │
   ├─► اجرای tor.exe (یا باینری تور) با torrc سفارشی
   │
   ├─► اتصال به پورت کنترل (پیش‌فرض 9051) از طریق stem
   │      └─► سیگنال NEWNYM، اطلاعات مدار، آمار ترافیک
   │
   └─► پروکسی SOCKS5 روی 127.0.0.1:9050 (برای مرورگرها و برنامه‌ها)
```

- **پورت کنترل (9051)** – فقط برای دستورات داخلی استفاده می‌شود.  
- **پورت SOCKS5 (9050)** – همان پورتی است که در فایرفاکس، کرل و غیره تنظیم می‌کنید.

**روش‌های احراز هویت** – بدون رمز (پیش‌فرض)، رمز عبور یا فایل کوکی.

**Bridge و Obfs4** – می‌توانید خطوط Bridge (حاوی `obfs4`) را در GUI وارد کنید.  
ConTor به طور خودکار خطوط `UseBridges 1` و `ClientTransportPlugin` را به `torrc` اضافه می‌کند.

---

# 🌐 3. DNS Scanner / اسکنر DNS

**English**  
The scanner performs **active reconnaissance** on a given IPv4 CIDR range (e.g., `8.8.8.0/24`).

| Probe | Port | Protocol | Purpose |
|-------|------|----------|---------|
| UDP 53 | 53 | UDP | Standard DNS – fastest |
| TCP 53 | 53 | TCP | More reliable over lossy links |
| DoT (DNS over TLS) | 853 | TCP + TLS | Privacy‑oriented resolvers |
| DoH (DNS over HTTPS) | 443 | TCP + TLS | Web‑based resolvers |

**Fake DNS Detection** – To detect **DNS hijacking**, the scanner:
1. Generates a random non‑existent domain.
2. Sends a query to the target resolver.
3. If the resolver returns `NOERROR` + Answer → the resolver is marked **"Fake/Hijacked"**.

**فارسی**  
اسکنر یک **پویش فعال** روی یک محدوده CIDR آی‌پی ورودی (مثل `8.8.8.0/24`) انجام می‌دهد.

| نوع پروب | پورت | پروتکل | هدف |
|----------|------|--------|------|
| UDP 53 | 53 | UDP | DNS استاندارد – سریع‌ترین |
| TCP 53 | 53 | TCP | قابل اطمینان‌تر روی اتصالات پرخطا |
| DoT (DNS روی TLS) | 853 | TCP + TLS | رزلورهای متمرکز بر حریم خصوصی |
| DoH (DNS روی HTTPS) | 443 | TCP + TLS | رزلورهای مبتنی بر وب |

**تشخیص DNS جعلی (ربودگی)** – اسکنر برای شناسایی ربوده شدن DNS:
1. یک دامنه تصادفی ناموجود تولید می‌کند.
2. درخواست را به رزلور هدف می‌فرستد.
3. اگر رزلور پاسخ `NOERROR` به همراه جواب برگرداند → رزلور به عنوان **جعلی/ربوده شده** علامت می‌خورد.

---

# 🚀 4. DNS Proxy / پروکسی DNS

**English**  

```
Client (127.0.0.1:5353)
       │
       ▼
ConTor DNS Proxy
       │
       ├─► Cache (TTL 60s)
       │
       └─► Upstream servers (e.g., 1.1.1.1, 9.9.9.9, or scanned IPs)
```

- **UDP only** (typical DNS)
- In‑memory cache with LRU eviction (default 100 entries)
- Automatic failover – tries next upstream on timeout/error
- One‑click “Set as System DNS” (Windows only, requires admin)

**فارسی**  

```
کلاینت (127.0.0.1:5353)
       │
       ▼
پروکسی DNS ConTor
       │
       ├─► کش (TTL 60 ثانیه)
       │
       └─► سرورهای بالادست (مثلاً 1.1.1.1، 9.9.9.9 یا آی‌پی‌های اسکن شده)
```

- **فقط UDP** (DNS استاندارد)
- کش درون حافظه با حذف کم‌استفاده‌ترین (به‌طور پیش‌فرض ۱۰۰ ورودی)
- failover خودکار – در صورت تایم‌اوت یا خطا به بالادست بعدی می‌رود
- دکمه «تنظیم به عنوان DNS سیستم» (فقط ویندوز، نیاز به ادمین)

---

# ⚠️ 5. Threat Model / مدل تهدید

**English**  

### Assumed Capabilities
- Attacker can monitor local network traffic.
- Attacker can try to inject malicious DNS responses (if untrusted upstream is used).
- Attacker who compromises your machine can read Tor configuration and logs.

### ConTor’s Defenses
- Tor traffic is encrypted and routed through Tor network.
- DNS scanner sends no sensitive data – only availability tests.
- Local DNS proxy caches responses but does not log them persistently.
- No hardcoded credentials; passwords stored in JSON config (protect with file permissions).

### Limitations (Transparent)
- ❌ Tor does **not** provide perfect forward secrecy for long‑lived circuits (but you can rotate identity manually).
- ❌ DNS queries to upstream resolvers are not encrypted unless you use DoT/DoH upstreams (proxy supports plain DNS only).
- ❌ GUI runs with user privileges – desktop compromise affects Tor.

**فارسی**  

### توانمندی‌های فرض شده مهاجم
- مهاجم می‌تواند ترافیک شبکه محلی را شنود کند.
- مهاجم می‌تواند پاسخ‌های DNS مخرب تزریق کند (در صورت استفاده از بالادست غیرقابل اعتماد).
- مهاجمی که به دستگاه شما نفوذ کند می‌تواند تنظیمات و لاگ‌های تور را بخواند.

### دفاعیات ConTor
- ترافیک تور رمز شده و از شبکه تور عبور می‌کند.
- اسکنر DNS هیچ داده حساسی ارسال نمی‌کند – فقط تست در دسترس بودن.
- پروکسی DNS محلی پاسخ‌ها را کش می‌کند ولی به طور دائمی لاگ نمی‌کند.
- هیچ رمز سخت‌کد شده‌ای وجود ندارد؛ رمزها در فایل JSON ذخیره می‌شوند (با مجوزهای فایل محافظت کنید).

### محدودیت‌ها (شفاف)
- ❌ تور **محافظت از محرمانگی به جلو (PFS)** برای مدارهای بلندمدت فراهم نمی‌کند (اما می‌توانید هویت را دستی تغییر دهید).
- ❌ پرسش‌های DNS به سرورهای بالادست رمز نمی‌شوند مگر اینکه از بالادست‌های DoT/DoH استفاده کنید (پروکسی فقط DNS ساده را پشتیبانی می‌کند).
- ❌ رابط گرافیکی با سطح دسترسی کاربر اجرا می‌شود – نفوذ به دسکتاپ روی تور تأثیر می‌گذارد.

---

# 🔁 6. Comparison with Similar Tools / مقایسه با ابزارهای مشابه

| Feature / قابلیت | ConTor | Tor Browser Bundle | dnscrypt-proxy | zmap + dig |
|------------------|--------|--------------------|----------------|------------|
| Tor process management / مدیریت فرآیند Tor | ✅ GUI | ✅ (bundle) | ❌ | ❌ |
| DNS scanner (CIDR) / اسکنر DNS | ✅ | ❌ | ❌ | ✅ (اسکریپتی) |
| Fake detection / تشخیص فیک | ✅ | ❌ | ❌ | ❌ |
| DoT/DoH scanner / اسکنر DoT/DoH | ✅ | ❌ | ✅ (به عنوان کلاینت) | ❌ |
| Local DNS proxy / پروکسی DNS محلی | ✅ | ❌ | ✅ | ❌ |
| GUI / بدون خط فرمان | ✅ | ✅ | ❌ | ❌ |

---

# 🧩 7. Project Structure / ساختار پروژه

```
contor/
├── contor.py               # Main application (tkinter)
├── torrc                   # Generated Tor configuration
├── tor_dns_config.json     # Saved settings (auto‑created)
├── tor_data/               # Tor data directory (created at runtime)
├── vendor/                 # (optional) Place tor.exe / obfs4proxy here
├── README.md
├── LICENSE
└── .gitignore
```

No external dependencies besides `stem` (install with `pip install stem`).

---

# ⚙️ 8. Installation & Usage / نصب و استفاده

**English**  

### Requirements
- Python 3.7+
- Tor executable (download from [torproject.org](https://www.torproject.org/download/))
- `pip install stem`

### Quick Start
1. **Clone**  
   `git clone https://github.com/0xjafari/contor.git && cd contor`
2. **Install dependency**  
   `pip install stem`
3. **Run**  
   `python contor.py`
4. **Configure Tor path** – Click “Browse” and select your Tor binary.
5. **Start Tor** – Click **▶ Start**. Wait for “Tor started successfully”.
6. **Use Tor in browser** – Set proxy to `SOCKS5 127.0.0.1:9050`.
7. **Scan DNS** – Switch to DNS Scanner tab, enter CIDR, click Start Scan.
8. **Launch DNS proxy** – Right‑click a result → “Add to Proxy Upstreams”. Go to DNS Proxy tab → Start Proxy.

**فارسی**  

### پیش‌نیازها
- پایتون ۳.۷ یا بالاتر
- فایل اجرایی Tor (دانلود از [torproject.org](https://www.torproject.org/download/))
- `pip install stem`

### شروع سریع
۱. **کلون**  
   `git clone https://github.com/0xjafari/contor.git && cd contor`
۲. **نصب وابستگی**  
   `pip install stem`
۳. **اجرا**  
   `python contor.py`
۴. **تنظیم مسیر Tor** – روی «Browse» کلیک و فایل Tor را انتخاب کنید.
۵. **شروع Tor** – کلیک **▶ Start**. منتظر پیام «Tor started successfully» باشید.
۶. **استفاده از تور در مرورگر** – پروکسی را روی `SOCKS5 127.0.0.1:9050` تنظیم کنید.
۷. **اسکن DNS** – به تب DNS Scanner بروید، محدوده CIDR را وارد و Start Scan را بزنید.
۸. **راه‌اندازی پروکسی DNS** – روی یک نتیجه کلیک راست → «Add to Proxy Upstreams». به تب DNS Proxy بروید → Start Proxy.

---

# 📂 9. Logging & Privacy / لاگ‌ها و حریم خصوصی

**English**  
- Logs are displayed inside the GUI and can be exported manually (Tools → Export Log).
- The log **never** contains:
  - Private keys or passwords
  - Full DNS query contents (only metadata like IP and latency)
  - Tor circuit details (unless you click “Show Circuit”)
- Log files are stored only if you explicitly export them.

**فارسی**  
- لاگ‌ها در داخل رابط گرافیکی نمایش داده می‌شوند و می‌توانید دستی آن‌ها را خروجی بگیرید (Tools → Export Log).
- لاگ **هرگز** شامل موارد زیر نیست:
  - کلیدهای خصوصی یا رمزها
  - محتویات کامل پرسش DNS (فقط فراداده مثل IP و تأخیر)
  - جزئیات مدار Tor (مگر اینکه روی «Show Circuit» کلیک کنید)
- فایل‌های لاگ فقط زمانی ذخیره می‌شوند که شما صریحاً خروجی بگیرید.

---

# ❗ 10. Limitations & Future Work / محدودیت‌ها و کارهای آتی

| Limitation (English) / محدودیت (فارسی) | Planned Improvement / بهبود برنامه‌ریزی شده |
|------------------------------------------|---------------------------------------------|
| No macOS/Linux “Set System DNS” automation | Add `networksetup` (macOS) and `resolvectl` (Linux) support |
| No DNSSEC validation | Could be added as a scanner option |
| TCP DNS proxy (instead of only UDP) | Low priority (UDP suffices for 99% of cases) |
| Dark theme only | Light theme is partially implemented but not complete |
| No built‑in Tor update mechanism | Provide a button to download the latest Tor bundle |

---

# 🛡 11. Security Recommendations / توصیه‌های امنیتی

**English**  
If you intend to use ConTor in a security‑sensitive environment:
- ✅ **Run Tor as a dedicated user** (not root/Administrator).
- ✅ **Use bridges** to hide Tor usage from your ISP.
- ✅ **Set a strong ControlPort password** (instead of “none”).
- ✅ **Restrict permissions** on `tor_dns_config.json` (e.g., `chmod 600`).
- ✅ **Only use DNS servers you trust** – scanned servers may be malicious or log queries.

**فارسی**  
اگر قصد استفاده از ConTor را در محیط حساس امنیتی دارید:
- ✅ **Tor را با کاربری مجزا اجرا کنید** (نه root/Administrator).
- ✅ **از Bridge استفاده کنید** تا استفاده از تور از دید ISP پنهان شود.
- ✅ **یک رمز قوی برای ControlPort** تعیین کنید (به جای «none»).
- ✅ **دسترسی به فایل `tor_dns_config.json` را محدود کنید** (مثلاً `chmod 600`).
- ✅ **فقط از سرورهای DNS معتبر استفاده کنید** – سرورهای اسکن شده ممکن است مخرب یا لاگر باشند.

---

# 🎯 12. Target Audience & Intended Use / کاربران هدف و کاربرد مجاز

**English**  

ConTor is designed for:

- **Security professionals and penetration testers** – to audit DNS security, discover open resolvers, and test Tor integration in controlled environments.
- **IT activists, journalists, and privacy‑conscious users** – to strengthen online anonymity and bypass censorship when used responsibly and legally.
- **Network administrators** – to verify DNS configuration, detect rogue resolvers, and deploy local DNS proxies.
- **Researchers and educators** – to learn about Tor, DNS protocols, and GUI application design.

### Intended purposes (legitimate and ethical)

- ✅ **Enhancing privacy and anonymity** – routing traffic through Tor to protect identity and location.
- ✅ **DNS security assessment** – scanning your own networks or explicitly authorized ranges to find misconfigured or open resolvers.
- ✅ **Bypassing censorship** – only in countries where using Tor is legal and for accessing information lawfully.
- ✅ **Educational use** – understanding how hybrid systems (Tor + DNS) work and how to build secure tools.

**فارسی**  

ConTor برای افراد زیر طراحی شده است:

- **متخصصان امنیت و تست‌کنندگان نفوذ** – برای ممیزی امنیت DNS، کشف رزلورهای باز و تست یکپارچگی تور در محیط‌های کنترل‌شده.
- **فعالان فناوری اطلاعات، روزنامه‌نگاران و کاربران دغدغه‌مند حریم خصوصی** – برای تقویت گمنامی آنلاین و دور زدن سانسور، به شرط استفاده مسئولانه و قانونی.
- **مدیران شبکه** – برای تأیید پیکربندی DNS، تشخیص رزلورهای مخرب و راه‌اندازی پروکسی DNS محلی.
- **محققان و مدرسان** – برای یادگیری تور، پروتکل‌های DNS و طراحی برنامه‌های کاربردی گرافیکی.

### کاربردهای مجاز (قانونی و اخلاقی)

- ✅ **افزایش حریم خصوصی و گمنامی** – هدایت ترافیک از طریق تور برای مخفی کردن هویت و مکان.
- ✅ **ارزیابی امنیت DNS** – اسکن شبکه‌های خودتان یا محدوده‌هایی که صراحتاً مجوز دارید، برای یافتن رزلورهای بد پیکربندی یا باز.
- ✅ **دور زدن سانسور** – تنها در کشورهایی که استفاده از تور قانونی است و برای دسترسی قانونی به اطلاعات.
- ✅ **استفاده آموزشی** – درک نحوه کار سیستم‌های ترکیبی (تور + DNS) و ساخت ابزارهای امن.

---

# 🚫 13. Prohibited Use & Disclaimer / کاربری ممنوع و سلب مسئولیت

**English**  

### Strictly prohibited activities

By using ConTor, you agree **NOT** to use it for:

- ❌ **Any illegal activity** under your local, national, or international laws.
- ❌ **Identity forgery, impersonation, or fraud** – including pretending to be someone else online.
- ❌ **Bypassing laws or sanctions** where Tor or DNS scanning is explicitly forbidden.
- ❌ **Harming others** – launching attacks, scanning networks without permission, doxing, stalking, or harassment.
- ❌ **Cyber‑attacks** – including but not limited to DDoS, DNS amplification attacks, or exploiting discovered resolvers for malicious purposes.
- ❌ **Child exploitation, terrorism, or any violence‑promoting activities**.
- ❌ **Spamming or spreading malware** via Tor or DNS proxies.
- ❌ **Reverse engineering, reselling, or redistributing ConTor as a commercial service** without prior written consent.

### Disclaimer of liability

> **THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**

Additionally, the developer (and any contributors) **assume no responsibility** for:

- Any misuse of ConTor that violates laws or third‑party rights.
- Any damage caused by scanning networks without authorization.
- Loss of anonymity due to incorrect configuration or use of malicious exit nodes.
- Legal consequences resulting from using ConTor in jurisdictions where Tor or DNS scanning is prohibited.

You are solely responsible for complying with all applicable laws and obtaining proper authorization before scanning any network or using Tor in a restricted environment.

**فارسی**  

### فعالیت‌های اکیداً ممنوع

با استفاده از ConTor، شما موافقت می‌کنید که از آن **برای موارد زیر استفاده نکنید**:

- ❌ **هرگونه فعالیت غیرقانونی** طبق قوانین محلی، ملی یا بین‌المللی.
- ❌ **جعل هویت، تظاهر به دیگری یا کلاه‌برداری** – شامل وانمود کردن به شخص دیگری در فضای مجازی.
- ❌ **دور زدن قوانین یا تحریم‌ها** در جایی که استفاده از تور یا اسکن DNS صراحتاً ممنوع است.
- ❌ **آسیب به دیگران** – راه‌اندازی حملات، اسکن شبکه بدون اجازه، اشاعه اطلاعات شخصی، تعقیب آنلاین یا آزار.
- ❌ **حملات سایبری** – شامل اما نه محدود به DDoS، حملات تقویت DNS یا سوءاستفاده از رزلورهای کشف شده برای اهداف مخرب.
- ❌ **استثمار کودکان، تروریسم یا هرگونه فعالیت ترویج‌دهنده خشونت**.
- ❌ **اسپم یا انتشار بدافزار** از طریق تور یا پروکسی‌های DNS.
- ❌ **مهندسی معکوس، فروش مجدد یا توزیع مجدد ConTor به عنوان سرویس تجاری** بدون کسب اجازه کتبی قبلی.

### سلب مسئولیت

> **نرم‌افزار «همان‌طور که هست» و بدون هرگونه ضمانت، صریح یا ضمنی، از جمله اما نه محدود به ضمانت‌های قابلیت فروش، تناسب برای یک هدف خاص و عدم نقض حقوق دیگران ارائه می‌شود. در هیچ حالتی نویسندگان یا دارندگان کپی‌رایت در قبال هیچ ادعا، خسارت یا مسئولیت دیگری، خواه در یک اقدام قراردادی یا تخلفی، ناشی از یا در ارتباط با نرم‌افزار یا استفاده یا معاملات دیگر در نرم‌افزار مسئول نخواهند بود.**

علاوه بر این، توسعه‌دهنده (و هر مشارکت‌کننده) **هیچ مسئولیتی** در قبال موارد زیر نمی‌پذیرد:

- هرگونه سوءاستفاده از ConTor که قوانین یا حقوق اشخاص ثالث را نقض کند.
- هرگونه خسارت ناشی از اسکن شبکه‌ها بدون مجوز.
- از دست رفتن گمنامی به دلیل پیکربندی نادرست یا استفاده از نودهای خروجی مخرب.
- عواقب قانونی ناشی از استفاده از ConTor در حوزه‌های قضایی که استفاده از تور یا اسکن DNS ممنوع است.

شما تنها مسئول رعایت تمام قوانین قابل اعمال و اخذ مجوز مناسب قبل از اسکن هر شبکه یا استفاده از تور در محیط‌های محدود شده هستید.

---

# 📜 14. License (GNU GPLv3) / مجوز GNU GPLv3

**English**  
ConTor is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.**

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

### Why GPLv3?

- ✅ **Ensures ConTor and any derivative work remain open source** (copyleft).
- ✅ **Allows non‑commercial and commercial use as long as the source code of the whole work is released under GPLv3** (freedom, not charity).
- ✅ **Includes an explicit disclaimer of warranty and liability**.
- ✅ **Compatible with Tor's BSD license** (Tor is an external process, not a linked library).

**Note:** If you distribute a modified version of ConTor (or any software that incorporates ConTor code), you **must** make the complete corresponding source code available under the GPLv3 as well.

**فارسی**  
ConTor نرم‌افزاری آزاد است: می‌توانید آن را تحت شرایط **مجوز عمومی همگانی گنو (GNU GPL) نسخه ۳** یا هر نسخه بعدتر (به انتخاب خود) توزیع و تغییر دهید.

این برنامه به این امید توزیع می‌شود که مفید باشد، اما **هیچ ضمانتی** ندارد؛ حتی ضمانت ضمنی قابلیت فروش یا مناسب بودن برای یک هدف خاص. برای جزئیات بیشتر، متن کامل مجوز GPL را مطالعه کنید.

نسخه‌ای از مجوز GPL باید به همراه این برنامه دریافت کرده باشید. در غیر این صورت، به <https://www.gnu.org/licenses/> مراجعه کنید.

### چرا GPLv3؟

- ✅ **تضمین می‌کند که ConTor و هر اثر مشتق شده، متن‌باز بمانند** (کپی‌لفت).
- ✅ **استفاده تجاری و غیرتجاری را اجازه می‌دهد، به شرطی که کد منبع کل اثر تحت GPLv3 منتشر شود** (آزادی، نه خیریه).
- ✅ **شامل سلب مسئولیت صریح در مورد هرگونه ضمانت و مسئولیت است**.
- ✅ **با مجوز BSD تور سازگار است** (تور یک فرآیند خارجی است، نه کتابخانه متصل).

**توجه:** اگر نسخه تغییر یافته‌ای از ConTor (یا هر نرم‌افزاری که کد ConTor را در خود دارد) توزیع کنید، شما **موظف هستید** که کد منبع کامل را تحت GPLv3 در دسترس قرار دهید.



<div align="center">

## 🔌 Tor + DNS – One Powerful GUI / یک رابط گرافیکی قدرتمند

**No command line required. No database. Just privacy & discovery.**  
**نیاز به خط فرمان ندارد. بدون پایگاه داده. فقط حریم خصوصی و کشف.**

**Use responsibly. Stay legal. Stay ethical. Keep it open.**  
**مسئولانه استفاده کنید. قانونی بمانید. اخلاقی بمانید. آن را باز نگه دارید.**

Version 5.3  
Architecture: Tor Controller + DNS Scanner + Local Proxy / معماری: کنترلر تور + اسکنر DNS + پروکسی محلی  
License: GNU General Public License v3.0 / مجوز عمومی همگانی گنو نسخه ۳  

</div>
