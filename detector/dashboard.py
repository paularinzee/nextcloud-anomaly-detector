"""
Live metrics dashboard.

A single self-contained HTML page that polls /api/state every 3 seconds
and renders: banned IPs, global req/s, top 10 source IPs, CPU/mem,
effective mean/stddev, uptime, recent alerts, and a baseline-mean chart
broken down by hour-slot (this is what produces the Baseline-graph.png
screenshot).
"""
import logging
import time
from datetime import datetime

import psutil
import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

log = logging.getLogger("dashboard")


HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HNG Anomaly Detector</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0a0e27;
      --bg-2: #0f1535;
      --card: rgba(21, 27, 61, 0.55);
      --border: rgba(168, 85, 247, 0.18);
      --border-bright: rgba(0, 217, 255, 0.45);
      --text: #e2e8f0;
      --text-muted: #94a3b8;
      --accent: #00d9ff;
      --accent-2: #a855f7;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --pink: #ec4899;
      --grad-cool: linear-gradient(135deg, #00d9ff 0%, #a855f7 100%);
      --grad-warm: linear-gradient(135deg, #ec4899 0%, #f59e0b 100%);
      --grad-good: linear-gradient(135deg, #10b981 0%, #00d9ff 100%);
      --grad-bad:  linear-gradient(135deg, #ec4899 0%, #ef4444 100%);
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    html, body {
      background: var(--bg);
      color: var(--text);
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 14px;
      line-height: 1.5;
      min-height: 100vh;
      overflow-x: hidden;
      -webkit-font-smoothing: antialiased;
    }

    /* Ambient gradient blobs */
    body::before {
      content: '';
      position: fixed;
      inset: 0;
      background:
        radial-gradient(circle at 15% 0%, rgba(0, 217, 255, 0.10) 0%, transparent 45%),
        radial-gradient(circle at 90% 25%, rgba(236, 72, 153, 0.08) 0%, transparent 40%),
        radial-gradient(circle at 80% 100%, rgba(168, 85, 247, 0.10) 0%, transparent 50%);
      pointer-events: none;
      z-index: 0;
    }

    .container {
      position: relative;
      z-index: 1;
      max-width: 1600px;
      margin: 0 auto;
      padding: 24px;
    }

    /* ============= header ============= */
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px 0 28px;
      flex-wrap: wrap;
      gap: 16px;
    }

    .brand { display: flex; align-items: center; gap: 14px; }

    .logo {
      width: 40px; height: 40px;
      border-radius: 12px;
      background: var(--grad-cool);
      display: flex; align-items: center; justify-content: center;
      font-weight: 800; color: white; font-size: 18px;
      box-shadow: 0 6px 24px rgba(0, 217, 255, 0.35),
                  inset 0 1px 0 rgba(255,255,255,0.2);
      letter-spacing: -0.05em;
    }

    h1 {
      font-size: 19px;
      font-weight: 700;
      background: var(--grad-cool);
      -webkit-background-clip: text;
      background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: -0.02em;
    }

    .subtitle {
      font-size: 12px;
      color: var(--text-muted);
      font-weight: 500;
    }

    .status-bar {
      display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
    }

    .status-pill {
      display: inline-flex; align-items: center; gap: 8px;
      padding: 8px 14px;
      border-radius: 999px;
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.3);
      color: var(--success);
      font-size: 12px;
      font-weight: 600;
      transition: all 0.2s;
    }

    .status-pill.danger {
      background: rgba(239, 68, 68, 0.1);
      border-color: rgba(239, 68, 68, 0.4);
      color: var(--danger);
    }

    .pulse-dot {
      width: 8px; height: 8px;
      border-radius: 50%;
      background: var(--success);
      box-shadow: 0 0 0 0 var(--success);
      animation: pulse 2s infinite;
    }
    .status-pill.danger .pulse-dot { background: var(--danger); }

    @keyframes pulse {
      0%   { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
      70%  { box-shadow: 0 0 0 10px rgba(16, 185, 129, 0); }
      100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    .clock {
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
      color: var(--text-muted);
      padding: 8px 12px;
      background: rgba(168, 85, 247, 0.08);
      border-radius: 8px;
      border: 1px solid var(--border);
    }

    /* ============= hero stats ============= */
    .hero {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 20px;
    }

    .stat-card {
      background: var(--card);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 20px;
      position: relative;
      overflow: hidden;
      transition: transform 0.25s ease, border-color 0.25s, box-shadow 0.25s;
    }
    .stat-card:hover {
      transform: translateY(-3px);
      border-color: var(--border-bright);
      box-shadow: 0 12px 40px rgba(0, 217, 255, 0.12);
    }
    .stat-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 3px;
      background: var(--grad-cool);
    }
    .stat-card.success::before { background: var(--grad-good); }
    .stat-card.danger::before  { background: var(--grad-bad); }
    .stat-card.warning::before { background: var(--grad-warm); }

    .stat-label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      font-weight: 600;
      margin-bottom: 10px;
    }

    .stat-value {
      font-size: 34px;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
      color: var(--text);
      line-height: 1.1;
      letter-spacing: -0.03em;
      transition: color 0.3s ease;
    }
    .stat-value.danger  { color: var(--danger); }
    .stat-value.warning { color: var(--warning); }
    .stat-value.success { color: var(--success); }
    .stat-value.accent  { color: var(--accent); }

    .stat-meta {
      font-size: 11px;
      color: var(--text-muted);
      margin-top: 8px;
      font-weight: 500;
    }

    /* ============= main grid ============= */
    .grid {
      display: grid;
      grid-template-columns: repeat(12, 1fr);
      gap: 16px;
    }

    .card {
      background: var(--card);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 22px;
      transition: border-color 0.25s, box-shadow 0.25s;
    }
    .card:hover { border-color: var(--border-bright); }

    .card h2 {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--text-muted);
      font-weight: 700;
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .card h2 .count {
      background: var(--grad-cool);
      -webkit-background-clip: text;
      background-clip: text;
      -webkit-text-fill-color: transparent;
      font-size: 13px;
      font-weight: 800;
    }

    .col-12 { grid-column: span 12; }
    .col-8  { grid-column: span 8;  }
    .col-6  { grid-column: span 6;  }
    .col-4  { grid-column: span 4;  }

    @media (max-width: 1024px) {
      .col-8 { grid-column: span 12; }
      .col-6 { grid-column: span 12; }
      .col-4 { grid-column: span 12; }
    }

    /* ============= tables ============= */
    table { width: 100%; border-collapse: collapse; font-size: 13px; }

    th {
      text-align: left;
      padding: 10px 8px;
      color: var(--text-muted);
      font-weight: 600;
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      border-bottom: 1px solid var(--border);
    }

    td {
      padding: 12px 8px;
      border-bottom: 1px solid rgba(148, 163, 184, 0.06);
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      vertical-align: middle;
    }

    tbody tr { transition: background 0.15s; }
    tbody tr:hover { background: rgba(0, 217, 255, 0.04); }

    .empty {
      color: var(--text-muted);
      font-style: italic;
      text-align: center;
      padding: 28px 8px !important;
      font-family: 'Inter', sans-serif !important;
    }

    /* ============= top IP bars ============= */
    .ip-bars { display: flex; flex-direction: column; gap: 10px; }
    .ip-bar {
      display: grid;
      grid-template-columns: 150px 1fr 50px;
      align-items: center;
      gap: 12px;
      font-size: 12px;
      font-family: 'JetBrains Mono', monospace;
    }
    .ip-bar .ip { color: var(--text); font-weight: 500; }
    .ip-bar .bar {
      height: 10px;
      background: rgba(168, 85, 247, 0.1);
      border-radius: 5px;
      overflow: hidden;
    }
    .ip-bar .fill {
      height: 100%;
      background: var(--grad-cool);
      border-radius: 5px;
      transition: width 0.5s cubic-bezier(0.16, 1, 0.3, 1);
      box-shadow: 0 0 12px rgba(0, 217, 255, 0.4);
    }
    .ip-bar .count {
      text-align: right;
      color: var(--accent);
      font-weight: 700;
    }

    @media (max-width: 600px) {
      .ip-bar { grid-template-columns: 110px 1fr 40px; }
    }

    /* ============= ban styling ============= */
    .ban-ip   { color: var(--danger); font-weight: 700; }
    .ban-count {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 12px;
      background: rgba(239, 68, 68, 0.12);
      color: var(--danger);
      font-size: 11px;
      font-weight: 700;
      border: 1px solid rgba(239, 68, 68, 0.25);
    }
    .ban-perm {
      color: var(--warning);
      font-weight: 700;
      font-size: 11px;
    }

    /* ============= alert badges ============= */
    .badge {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 12px;
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border: 1px solid transparent;
    }
    .badge.per_ip {
      background: rgba(239, 68, 68, 0.12);
      color: var(--danger);
      border-color: rgba(239, 68, 68, 0.3);
    }
    .badge.global {
      background: rgba(245, 158, 11, 0.12);
      color: var(--warning);
      border-color: rgba(245, 158, 11, 0.3);
    }

    /* ============= progress bars ============= */
    .progress { display: flex; flex-direction: column; gap: 14px; }
    .progress-row {
      display: grid;
      grid-template-columns: 60px 1fr 56px;
      gap: 12px;
      align-items: center;
      font-size: 12px;
    }
    .progress-row .label {
      color: var(--text-muted);
      text-transform: uppercase;
      font-size: 10px;
      letter-spacing: 0.08em;
      font-weight: 700;
    }
    .progress-row .bar {
      height: 10px;
      background: rgba(168, 85, 247, 0.1);
      border-radius: 5px;
      overflow: hidden;
    }
    .progress-row .fill {
      height: 100%;
      background: var(--grad-good);
      border-radius: 5px;
      transition: width 0.4s ease, background 0.3s;
      box-shadow: 0 0 8px rgba(16, 185, 129, 0.4);
    }
    .progress-row .fill.warn {
      background: var(--grad-warm);
      box-shadow: 0 0 10px rgba(245, 158, 11, 0.5);
    }
    .progress-row .fill.crit {
      background: var(--grad-bad);
      box-shadow: 0 0 12px rgba(239, 68, 68, 0.5);
    }
    .progress-row .val {
      font-family: 'JetBrains Mono', monospace;
      text-align: right;
      color: var(--text);
      font-weight: 700;
    }

    /* ============= chart canvas ============= */
    canvas { display: block; width: 100%; height: 260px; }

    /* ============= toast notifications ============= */
    .toast-stack {
      position: fixed;
      top: 20px; right: 20px;
      z-index: 100;
      display: flex; flex-direction: column; gap: 10px;
      max-width: 360px;
      pointer-events: none;
    }
    .toast {
      background: rgba(15, 21, 53, 0.95);
      backdrop-filter: blur(12px);
      border: 1px solid var(--border-bright);
      border-radius: 14px;
      padding: 14px 16px;
      box-shadow: 0 12px 48px rgba(0, 0, 0, 0.5);
      animation: slideIn 0.3s cubic-bezier(0.16, 1, 0.3, 1);
      font-size: 13px;
      pointer-events: auto;
    }
    .toast.danger  { border-color: rgba(239, 68, 68, 0.5); }
    .toast.warning { border-color: rgba(245, 158, 11, 0.5); }
    .toast strong  { color: var(--accent); }
    .toast.danger strong  { color: var(--danger); }
    .toast.warning strong { color: var(--warning); }
    .toast .toast-meta {
      color: var(--text-muted);
      font-size: 11px;
      margin-top: 4px;
      display: block;
    }
    .toast code {
      background: rgba(0, 217, 255, 0.1);
      color: var(--accent);
      padding: 1px 6px;
      border-radius: 4px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
    }

    @keyframes slideIn {
      from { transform: translateX(120%); opacity: 0; }
      to   { transform: translateX(0); opacity: 1; }
    }

    /* ============= footer ============= */
    footer {
      margin-top: 36px;
      padding: 18px 0;
      text-align: center;
      color: var(--text-muted);
      font-size: 11px;
      border-top: 1px solid var(--border);
    }
    footer .accent { color: var(--accent); font-weight: 600; }

    @media (max-width: 600px) {
      .container { padding: 16px; }
      .stat-value { font-size: 26px; }
      h1 { font-size: 16px; }
      .card { padding: 16px; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <div class="logo">H</div>
        <div>
          <h1>HNG Anomaly Detector</h1>
          <div class="subtitle">Real-time HTTP traffic anomaly detection</div>
        </div>
      </div>
      <div class="status-bar">
        <div class="status-pill" id="status">
          <span class="pulse-dot"></span>
          <span id="status-text">live</span>
        </div>
        <div class="clock" id="clock">--:--:--</div>
      </div>
    </header>

    <div class="hero">
      <div class="stat-card">
        <div class="stat-label">Global req/s</div>
        <div class="stat-value" id="grate">0.00</div>
        <div class="stat-meta">last 60s window</div>
      </div>
      <div class="stat-card success">
        <div class="stat-label">Effective baseline</div>
        <div class="stat-value" id="bmean">0.00</div>
        <div class="stat-meta">stddev <span id="bstd">0.00</span> · slot h<span id="bslot">--</span></div>
      </div>
      <div class="stat-card danger">
        <div class="stat-label">Banned IPs</div>
        <div class="stat-value" id="bcount-hero">0</div>
        <div class="stat-meta" id="bcount-meta">none active</div>
      </div>
      <div class="stat-card warning">
        <div class="stat-label">Uptime</div>
        <div class="stat-value" id="uptime" style="font-size: 24px;">0h 0m 0s</div>
        <div class="stat-meta">since daemon start</div>
      </div>
    </div>

    <div class="grid">
      <div class="card col-8">
        <h2>Baseline mean over time</h2>
        <canvas id="chart"></canvas>
      </div>

      <div class="card col-4">
        <h2>System</h2>
        <div class="progress">
          <div class="progress-row">
            <span class="label">CPU</span>
            <div class="bar"><div class="fill" id="cpu-bar" style="width: 0%"></div></div>
            <span class="val" id="cpu-val">0%</span>
          </div>
          <div class="progress-row">
            <span class="label">Memory</span>
            <div class="bar"><div class="fill" id="mem-bar" style="width: 0%"></div></div>
            <span class="val" id="mem-val">0%</span>
          </div>
        </div>
      </div>

      <div class="card col-6">
        <h2>Top source IPs <span class="count" id="topcount">0</span></h2>
        <div id="top" class="ip-bars"></div>
      </div>

      <div class="card col-6">
        <h2>Banned IPs <span class="count" id="bcount">0</span></h2>
        <table>
          <thead><tr><th>IP</th><th>Bans</th><th>Release</th></tr></thead>
          <tbody id="banned"></tbody>
        </table>
      </div>

      <div class="card col-12">
        <h2>Recent alerts <span class="count" id="acount">0</span></h2>
        <table>
          <thead><tr>
            <th>Time</th><th>Kind</th><th>Source</th>
            <th>Rate</th><th>Baseline</th><th>Condition</th>
          </tr></thead>
          <tbody id="alerts"></tbody>
        </table>
      </div>
    </div>

    <footer>
      Refreshes every <span class="accent">3s</span> ·
      HNG Internship Stage 3 · DevOps
    </footer>
  </div>

  <div class="toast-stack" id="toasts"></div>

<script>
// Return the first DOM element matching a CSS selector.
const $ = (s) => document.querySelector(s);
const HOUR_COLORS = [
  "#00d9ff","#a855f7","#10b981","#f59e0b","#ec4899","#ef4444",
  "#3b82f6","#84cc16","#f97316","#06b6d4","#8b5cf6","#14b8a6"
];

let lastAlertTs = null;
let bootstrapped = false;

function fmtUnban(ts) {
  // Convert a Unix unban timestamp into the compact release text shown in the UI.
  if (ts === null || ts === undefined) {
    return '<span class="ban-perm">PERMANENT</span>';
  }
  const d = new Date(ts * 1000);
  const diff = Math.floor((d - new Date()) / 1000);
  if (diff < 0) return 'releasing…';
  if (diff < 60) return 'in ' + diff + 's';
  if (diff < 3600) return 'in ' + Math.floor(diff/60) + 'm';
  return 'in ' + Math.floor(diff/3600) + 'h ' + Math.floor((diff%3600)/60) + 'm';
}

function colorForRate(rate, mean) {
  // Choose a visual status class based on how far current traffic is above baseline.
  if (mean <= 0) return null;
  const ratio = rate / mean;
  if (ratio > 5) return 'danger';
  if (ratio > 3) return 'warning';
  if (ratio > 1.5) return 'accent';
  return 'success';
}

function showToast(alert) {
  // Render a temporary notification for a new global or per-IP alert.
  const stack = $('#toasts');
  const el = document.createElement('div');
  const isGlobal = alert.kind === 'global';
  el.className = 'toast ' + (isGlobal ? 'warning' : 'danger');
  const icon = isGlobal ? '⚠' : '⛔';
  el.innerHTML =
    icon + ' <strong>' + (isGlobal ? 'Global anomaly' : 'IP banned') + '</strong>' +
    '<br><code>' + alert.ip + '</code> · ' + alert.rate.toFixed(2) + ' req/s' +
    '<span class="toast-meta">' + alert.condition + '</span>';
  stack.prepend(el);
  setTimeout(() => {
    el.style.transition = 'opacity 0.5s, transform 0.5s';
    el.style.opacity = '0';
    el.style.transform = 'translateX(120%)';
    setTimeout(() => el.remove(), 500);
  }, 6500);
}

function drawChart(history) {
  // Draw the baseline history chart, including grid lines, fill, line, points, and legend.
  const c = $("#chart");
  if (!c) return;
  const dpr = window.devicePixelRatio || 1;
  const W = c.clientWidth, H = 260;
  c.width = W * dpr; c.height = H * dpr;
  const ctx = c.getContext("2d");
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, W, H);

  if (!history || !history.length) {
    ctx.fillStyle = "#94a3b8";
    ctx.font = "13px Inter, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("Waiting for first baseline recalculation…", W/2, H/2);
    return;
  }

  const means = history.map(p => p.slot_mean);
  const max = Math.max(...means, 1) * 1.15;
  const padX = 56, padY = 24;
  const innerW = W - padX - 20, innerH = H - padY - 36;

  // grid + y labels
  ctx.strokeStyle = "rgba(168, 85, 247, 0.08)";
  ctx.lineWidth = 1;
  ctx.font = "10px 'JetBrains Mono', monospace";
  ctx.textAlign = "right";
  ctx.fillStyle = "#94a3b8";
  for (let i = 0; i <= 4; i++) {
    const y = padY + (innerH * i / 4);
    ctx.beginPath();
    ctx.moveTo(padX, y);
    ctx.lineTo(W - 20, y);
    ctx.stroke();
    ctx.fillText((max * (1 - i/4)).toFixed(2), padX - 8, y + 3);
  }

  // gradient fill under line
  const grad = ctx.createLinearGradient(0, padY, 0, H - 36);
  grad.addColorStop(0, 'rgba(0, 217, 255, 0.35)');
  grad.addColorStop(1, 'rgba(0, 217, 255, 0)');
  ctx.beginPath();
  history.forEach((p, i) => {
    const x = padX + innerW * (i / Math.max(1, history.length - 1));
    const y = padY + innerH * (1 - p.slot_mean / max);
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.lineTo(padX + innerW, H - 36);
  ctx.lineTo(padX, H - 36);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // line itself with glow
  ctx.beginPath();
  history.forEach((p, i) => {
    const x = padX + innerW * (i / Math.max(1, history.length - 1));
    const y = padY + innerH * (1 - p.slot_mean / max);
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = "#00d9ff";
  ctx.lineWidth = 2.5;
  ctx.shadowColor = "rgba(0, 217, 255, 0.6)";
  ctx.shadowBlur = 10;
  ctx.stroke();
  ctx.shadowBlur = 0;

  // hour-coloured points
  history.forEach((p, i) => {
    const x = padX + innerW * (i / Math.max(1, history.length - 1));
    const y = padY + innerH * (1 - p.slot_mean / max);
    ctx.fillStyle = HOUR_COLORS[p.hour % HOUR_COLORS.length];
    ctx.beginPath();
    ctx.arc(x, y, 4, 0, Math.PI * 2);
    ctx.fill();
    ctx.strokeStyle = "rgba(255,255,255,0.15)";
    ctx.lineWidth = 1;
    ctx.stroke();
  });

  // hour-slot legend
  const hours = [...new Set(history.map(p => p.hour))];
  let lx = padX;
  ctx.font = "11px Inter, sans-serif";
  ctx.textAlign = "left";
  hours.forEach(h => {
    ctx.fillStyle = HOUR_COLORS[h % HOUR_COLORS.length];
    ctx.beginPath();
    ctx.arc(lx, H - 14, 4, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = "#94a3b8";
    ctx.fillText('hour ' + h, lx + 8, H - 11);
    lx += 68;
    if (lx > W - 60) return;
  });
}

function renderTopIps(ips) {
  // Render the current busiest source IPs as proportional horizontal bars.
  const el = $('#top');
  $('#topcount').textContent = ips.length;
  if (!ips.length) {
    el.innerHTML = '<div class="empty">No active sources</div>';
    return;
  }
  const max = Math.max(...ips.map(([,n]) => n));
  el.innerHTML = ips.map(([ip, n]) => {
    const pct = (n / max * 100).toFixed(0);
    return '<div class="ip-bar">' +
      '<span class="ip">' + ip + '</span>' +
      '<div class="bar"><div class="fill" style="width:' + pct + '%"></div></div>' +
      '<span class="count">' + n + '</span>' +
      '</div>';
  }).join('');
}

function renderBanned(banned) {
  // Render the active ban table and keep the hero ban counter in sync.
  $('#bcount').textContent = banned.length;
  $('#bcount-hero').textContent = banned.length;
  $('#bcount-meta').textContent = banned.length ? 'currently active' : 'none active';
  const tb = $('#banned');
  if (!banned.length) {
    tb.innerHTML = '<tr><td colspan="3" class="empty">No bans active</td></tr>';
    return;
  }
  tb.innerHTML = banned.map(b =>
    '<tr>' +
      '<td><span class="ban-ip">' + b.ip + '</span></td>' +
      '<td><span class="ban-count">×' + b.ban_count + '</span></td>' +
      '<td>' + fmtUnban(b.unban_at) + '</td>' +
    '</tr>'
  ).join('');
}

function renderAlerts(alerts) {
  // Render recent alerts and show a toast only when a new alert arrives after load.
  $('#acount').textContent = alerts.length;
  const tb = $('#alerts');
  if (!alerts.length) {
    tb.innerHTML = '<tr><td colspan="6" class="empty">No alerts yet — system nominal</td></tr>';
  } else {
    tb.innerHTML = alerts.map(a => {
      const time = (a.ts.split('T')[1] || a.ts).slice(0, 8);
      return '<tr>' +
        '<td>' + time + '</td>' +
        '<td><span class="badge ' + a.kind + '">' + a.kind + '</span></td>' +
        '<td>' + a.ip + '</td>' +
        '<td>' + a.rate.toFixed(2) + '</td>' +
        '<td>' + a.baseline.toFixed(2) + '</td>' +
        '<td style="font-family: Inter, sans-serif; font-size: 11px; color: #94a3b8;">' +
          a.condition + '</td>' +
      '</tr>';
    }).join('');
  }

  // toast on a NEW alert (not on page load)
  if (alerts.length) {
    const newest = alerts[0];
    if (bootstrapped && newest.ts !== lastAlertTs) {
      showToast(newest);
    }
    lastAlertTs = newest.ts;
  }
}

function setStatus(connected) {
  // Toggle the dashboard connection pill between live and disconnected states.
  const p = $('#status');
  const t = $('#status-text');
  if (connected) {
    p.className = 'status-pill';
    t.textContent = 'live';
  } else {
    p.className = 'status-pill danger';
    t.textContent = 'disconnected';
  }
}

function tickClock() {
  // Refresh the client-side clock once per second.
  $('#clock').textContent = new Date().toLocaleTimeString();
}

function setProgress(barEl, valEl, pct) {
  // Update a system metric progress bar and apply warning/critical styling.
  valEl.textContent = pct.toFixed(1) + '%';
  barEl.style.width = Math.min(100, pct) + '%';
  let cls = 'fill';
  if (pct > 85)      cls += ' crit';
  else if (pct > 65) cls += ' warn';
  barEl.className = cls;
}

async function tick() {
  // Poll /api/state, refresh all dashboard widgets, and mark connection health.
  try {
    const r = await fetch('/api/state');
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const s = await r.json();
    setStatus(true);

    // hero
    const grate = s.global_rate;
    const mean = s.baseline.mean;
    $('#grate').textContent = grate.toFixed(2);
    const cls = colorForRate(grate, mean);
    $('#grate').className = 'stat-value' + (cls ? ' ' + cls : '');
    $('#bmean').textContent = mean.toFixed(2);
    $('#bstd').textContent = s.baseline.stddev.toFixed(2);
    $('#bslot').textContent = s.baseline.hour_slot;
    $('#uptime').textContent = s.system.uptime;

    // system
    setProgress($('#cpu-bar'), $('#cpu-val'), s.system.cpu);
    setProgress($('#mem-bar'), $('#mem-val'), s.system.mem);

    renderTopIps(s.top_ips);
    renderBanned(s.banned);
    renderAlerts(s.recent_alerts);
    drawChart(s.baseline_history);

    bootstrapped = true;
  } catch (e) {
    setStatus(false);
  }
}

tickClock();
setInterval(tickClock, 1000);
tick();
setInterval(tick, 3000);
</script>
</body>
</html>"""


class Dashboard:
    def __init__(self, cfg, detector, baseline, blocker):
        """Build the FastAPI dashboard around live detector components.

        The dashboard keeps references to detector, baseline, and blocker state
        so /api/state can expose real-time metrics without a separate database.
        """
        self.cfg = cfg
        self.detector = detector
        self.baseline = baseline
        self.blocker = blocker
        self.port = int(cfg.get("dashboard_port", 8080))
        self.host = cfg.get("dashboard_host", "0.0.0.0")
        self.start = time.time()

        self.app = FastAPI(title="HNG Anomaly Detector Dashboard")
        self._register()

    def _register(self) -> None:
        """Register HTML, health, and JSON state routes on the FastAPI app."""
        @self.app.get("/", response_class=HTMLResponse)
        async def index() -> HTMLResponse:
            """Serve the single-page dashboard shell."""
            return HTMLResponse(HTML)

        @self.app.get("/healthz")
        async def healthz() -> JSONResponse:
            """Return a lightweight readiness response for probes and smoke tests."""
            return JSONResponse({"ok": True})

        @self.app.get("/api/state")
        async def state() -> JSONResponse:
            """Return the current detector, baseline, blocker, and system metrics."""
            mean, stddev = self.baseline.effective()
            up_s = int(time.time() - self.start)
            h, rem = divmod(up_s, 3600)
            m, s = divmod(rem, 60)
            return JSONResponse({
                "global_rate": self.detector.global_rate(),
                "baseline": {
                    "mean": mean,
                    "stddev": stddev,
                    "hour_slot": datetime.now().hour,
                },
                "system": {
                    "cpu": psutil.cpu_percent(interval=None),
                    "mem": psutil.virtual_memory().percent,
                    "uptime": f"{h}h {m}m {s}s",
                },
                "banned": self.blocker.banned_list(),
                "top_ips": self.detector.top_ips(10),
                "recent_alerts": list(self.detector.recent_alerts),
                "baseline_history": list(self.baseline.history),
            })

    async def serve(self) -> None:
        """Run the FastAPI application with uvicorn until the task is cancelled."""
        config = uvicorn.Config(
            self.app, host=self.host, port=self.port, log_level="warning",
        )
        server = uvicorn.Server(config)
        await server.serve()
