// Daily-cost chart builder for the Settings page. Pure functions only —
// no DOM access — so the same file loads under Node for verification.
// Rendering rules follow the dataviz method: thin bars (≤24px) with 4px
// rounded tops and square baselines, 2px surface gaps between stacked
// segments, hairline gridlines, text in ink tokens (never series colors).
(function (global) {
  'use strict';

  // Dark categorical slots, validated (adjacent pairs, CVD + contrast)
  // against the card surface #242424. The ORDER is the safety mechanism —
  // never reshuffle it.
  const SERIES = ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#008300', '#9085e9', '#e66767'];

  // A model keeps its color across renders and ranges. Known ids get fixed
  // slots; unknown ids hash into the remaining slots deterministically.
  const MODEL_SLOT = {
    'claude-opus-5': 0,
    'gemini-2.5-pro': 1,
    'gemini-2.5-flash': 2,
    'gemini-2.5-flash-lite': 3,
    'claude-sonnet-4-6': 4
  };
  function slotOf(model) {
    if (MODEL_SLOT[model] !== undefined) return MODEL_SLOT[model];
    let h = 0;
    const s = String(model || '');
    for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
    return 5 + (h % 3);
  }
  const modelColor = model => SERIES[slotOf(model)];

  // $ formatting: compact for cards, adaptive decimals so small totals
  // never round to a bare $0.
  function fmtUsd(n) {
    n = Number(n) || 0;
    if (n === 0) return '$0';
    if (n >= 100) return '$' + Math.round(n).toLocaleString();
    if (n >= 1) return '$' + n.toFixed(2);
    if (n >= 0.01) return '$' + n.toFixed(2);
    return '$' + n.toFixed(3);
  }

  function fmtTok(t) {
    t = Number(t) || 0;
    if (t >= 1e6) return (t / 1e6).toFixed(1) + 'M';
    if (t >= 1000) return (t / 1000).toFixed(1) + 'k';
    return String(t);
  }

  // Chart data model from a /api/usage/summary response. Every calendar day
  // in [from, to] gets a slot (UTC days, matching the endpoint's grouping),
  // so zero-usage days render as visible gaps. Segments are stacked in fixed
  // slot order — the same adjacency the palette was validated for.
  function buildModel(summary) {
    const byDay = new Map((summary.by_day || []).map(d => [d.day, d]));
    const days = [];
    const startT = Date.parse(String(summary.from).slice(0, 10) + 'T00:00:00Z');
    const endT = Date.parse(String(summary.to).slice(0, 10) + 'T00:00:00Z');
    if (!isFinite(startT) || !isFinite(endT)) return { days: [], models: [], maxDay: 0 };
    for (let t = startT; t <= endT; t += 86400000) {
      const day = new Date(t).toISOString().slice(0, 10);
      const d = byDay.get(day);
      const segs = ((d && d.by_model) || [])
        .filter(m => (m.est_cost || 0) > 0)
        .sort((a, b) => (slotOf(a.model) - slotOf(b.model)) || (a.model < b.model ? -1 : 1));
      days.push({
        day,
        total: d ? (d.est_cost || 0) : 0,
        calls: d ? (d.calls || 0) : 0,
        segs
      });
    }
    const models = Array.from(new Set(days.flatMap(d => d.segs.map(s => s.model))))
      .sort((a, b) => (slotOf(a) - slotOf(b)) || (a < b ? -1 : 1));
    const maxDay = Math.max(0, ...days.map(d => d.total));
    return { days, models, maxDay };
  }

  // Clean dollar steps so ticks land on round numbers.
  function niceStep(maxY, ticks) {
    const raw = (maxY || 0) / ticks;
    const steps = [0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 50, 100, 200, 500];
    for (const s of steps) if (s >= raw) return s;
    return 1000;
  }
  function tickLabel(v, step) {
    if (v === 0) return '$0';
    const dp = step < 0.01 ? 3 : step < 1 ? 2 : 0;
    return '$' + v.toFixed(dp);
  }

  // SVG string for the chart. Only server-derived dates and numbers are
  // interpolated — model names never enter this string (they live in the
  // legend and tooltip, which the page builds with textContent).
  function svg(model, width) {
    const W = Math.max(300, Math.floor(width || 640));
    const H = 220;
    const M = { top: 8, right: 8, bottom: 24, left: 46 };
    const plotW = W - M.left - M.right;
    const plotH = H - M.top - M.bottom;
    const n = Math.max(1, model.days.length);
    const ticks = 4;
    const step = niceStep(model.maxDay || 0.004, ticks);
    const yMax = step * ticks;
    const y = v => M.top + plotH - (v / yMax) * plotH;
    const slotW = plotW / n;
    const barW = Math.max(3, Math.min(24, Math.floor(slotW * 0.62)));
    const r2 = n => Math.round(n * 100) / 100;

    let out = '';
    for (let i = 0; i <= ticks; i++) {
      const gy = r2(y(step * i));
      out += '<line x1="' + M.left + '" y1="' + gy + '" x2="' + (W - M.right) + '" y2="' + gy +
        '" stroke="' + (i === 0 ? '#3a3a38' : '#2e2e2c') + '" stroke-width="1"/>';
      out += '<text x="' + (M.left - 6) + '" y="' + r2(gy + 3.5) +
        '" text-anchor="end" font-size="10" fill="#898781" style="font-variant-numeric:tabular-nums">' +
        tickLabel(step * i, step) + '</text>';
    }

    const every = model.days.length > 14 ? 5 : (model.days.length > 7 ? 2 : 1);
    model.days.forEach((d, i) => {
      if (i % every !== 0) return;
      const parts = d.day.split('-');
      const label = Number(parts[1]) + '/' + Number(parts[2]);
      out += '<text x="' + r2(M.left + slotW * i + slotW / 2) + '" y="' + (H - 8) +
        '" text-anchor="middle" font-size="10" fill="#898781">' + label + '</text>';
    });

    model.days.forEach((d, i) => {
      // Full-column hit target under the segments: hovering anywhere in the
      // day shows the one-tooltip-every-series readout.
      out += '<rect class="col-hit" data-i="' + i + '" x="' + r2(M.left + slotW * i) +
        '" y="' + M.top + '" width="' + r2(slotW) + '" height="' + plotH + '" fill="transparent"/>';
      const x = r2(M.left + slotW * i + (slotW - barW) / 2);
      let acc = 0;
      d.segs.forEach((s, j) => {
        const isTop = j === d.segs.length - 1;
        const rawTop = y(acc + s.est_cost);
        const rawBottom = y(acc);
        acc += s.est_cost;
        // 2px surface gap between touching segments: 1px off the top of the
        // lower one, 1px off the bottom of the upper one.
        let t = rawTop + (isTop ? 0 : 1);
        let b = rawBottom - (j === 0 ? 0 : 1);
        if (b - t < 0.75) t = b - 0.75;   // a sliver stays visible
        const fill = modelColor(s.model);
        if (isTop && (b - t) > 5) {
          const rad = Math.min(4, barW / 2);
          out += '<path class="seg" data-i="' + i + '" d="M' + x + ',' + r2(b) +
            ' L' + x + ',' + r2(t + rad) +
            ' Q' + x + ',' + r2(t) + ' ' + r2(x + rad) + ',' + r2(t) +
            ' L' + r2(x + barW - rad) + ',' + r2(t) +
            ' Q' + r2(x + barW) + ',' + r2(t) + ' ' + r2(x + barW) + ',' + r2(t + rad) +
            ' L' + r2(x + barW) + ',' + r2(b) + ' Z" fill="' + fill + '"/>';
        } else {
          out += '<rect class="seg" data-i="' + i + '" x="' + x + '" y="' + r2(t) +
            '" width="' + barW + '" height="' + r2(b - t) + '" fill="' + fill + '"/>';
        }
      });
    });

    return '<svg width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H +
      '" role="img" aria-label="Daily cost by model">' + out + '</svg>';
  }

  const api = { SERIES, slotOf, modelColor, fmtUsd, fmtTok, buildModel, niceStep, tickLabel, svg };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else global.CostChart = api;
})(typeof window !== 'undefined' ? window : globalThis);
