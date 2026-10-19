<div align="center">

# 🔦 Breachlight

**A local, defensive personal security exposure dashboard.**
*Shine a light on where your data has leaked — then fix it.*

![Node](https://img.shields.io/badge/Node.js-24%2B-339933?logo=node.js&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?logo=typescript&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)
![License](https://img.shields.io/badge/usage-personal%20%26%20defensive-blue)

```
SCAN  →  IDENTIFY  →  PRIORITISE  →  EXPLAIN  →  SECURE
```

</div>

---

## ✨ What it does

| | |
|---|---|
| 🔍 **Finds exposure** | Checks your email against public breach intelligence sources |
| 🧭 **Prioritises** | Scores each breach by severity, recency and data types leaked |
| 🧠 **Explains** | Plain-English reasons for every finding |
| 🛠️ **Guides fixes** | Concrete next steps: rotate passwords, enable 2FA, freeze credit |
| 🔑 **No key needed** | Works out of the box; Have I Been Pwned is optional |

## 🛡️ Ground rules

> Breachlight **identifies exposure**. It never retrieves or displays stolen credentials, never logs in anywhere, never tests credentials against a service, and never enumerates accounts.

Everything runs on `localhost`. No telemetry.

## 🚀 Quick start

**Requires Node.js 24+** (uses the built-in `node:sqlite`, so there is no native build step).

```bash
npm install
cp .env.example .env        # Windows: copy .env.example .env
npm run dev
```

| Service | URL |
|---|---|
| 🖥️ Dashboard | http://localhost:5173 |
| ⚙️ API | http://localhost:5174 |

Production-style single server:

```bash
npm run build
npm start                   # http://localhost:5174
```

## 🧩 Data sources

| Source | Key required | Status |
|---|:---:|---|
| XposedOrNot | ❌ | ✅ Enabled by default |
| Breach catalogue (HIBP public) | ❌ | ✅ Enabled by default |
| Pwned Passwords (k-anonymity) | ❌ | ✅ Enabled by default |
| Domain security posture (Deep+) | ❌ | ✅ Enabled by default |
| Have I Been Pwned (authenticated) | ✅ | ⚪ Optional, set `HIBP_API_KEY` |

## 🎚️ Scan depths

| Depth | Covers |
|---|---|
| **Quick** | Email breach lookup |
| **Standard** | + password exposure checks |
| **Deep** | + domain security posture |
| **Maximum** | Everything, with the widest coverage |

## ⚙️ Configuration

All settings live in `.env` (see [`.env.example`](.env.example)). Every value has a working default.

| Variable | Default | Purpose |
|---|---|---|
| `PORT` / `WEB_PORT` | `5174` / `5173` | API and dashboard ports |
| `DATABASE_FILE` | `./data/scanner.db` | Local SQLite file |
| `HIBP_API_KEY` | *(empty)* | Enables the authenticated HIBP provider |
| `DEMO_PROVIDER_ENABLED` | `false` | Adds a clearly labelled synthetic source for testing |
| `PROVIDER_CONCURRENCY` | `4` | Provider fan-out limit |

## 🧪 Development

| Command | Purpose |
|---|---|
| `npm run dev` | API and dashboard together |
| `npm run typecheck` | Type-check server and web |
| `npm test` | Run the Vitest suite |
| `npm run build` | Build the web app to `dist/web` |

## 🔐 Privacy & security

- **Local only.** Your data stays in a local SQLite file under `data/`, which is git-ignored.
- **Secrets stay out of git.** `.env` is ignored; only `.env.example` is tracked.
- **Rate-limited, hardened API.** Built on `helmet`, `cors` and `express-rate-limit`.
- **Honest results.** If a source is not queried, coverage says so. Nothing is faked.

---

<div align="center">

*Built for defenders. Stay lit. 🔦*

</div>
