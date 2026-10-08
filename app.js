'use strict';
/* Nexo IGA — single-page frontend built on the Modernist design system (modernist.css).
   CSP forbids inline handlers and inline styles: events use delegation (data-* attributes)
   and dynamic sizes/colors are applied by paint() through the CSSOM. */

const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];

const state = {
  token: localStorage.getItem('nexo.session') || '',
  user: null,
  page: 'dashboard',
  credentials: [],
  status: null,
  dash: { credentialId: null, provider: null, period: 90, data: null },
  ids: { list: [], summary: null, type: 'all', provider: 'all', q: '', selected: null, detail: null },
  acc: { view: 'grants', prov: 'all', unused: false, q: '', grants: [], summary: null, projects: null, roles: null, accounts: null },
  risk: { rule: 'all', severity: null, findings: [], rules: [], ai: [] },
  priv: { rows: [], summary: null, standing: false, role: null },
  ueba: { data: null, category: null, selected: null },
  audit: { data: null, source: null, result: 'all', q: '', selected: null },
  comp: { fw: 'iso', frameworks: [], campaigns: [] },
  admin: { settings: null, users: [] },
};

/* ── constants ──────────────────────────────────────────────────────── */
const NAV = [
  ['dashboard', 'Visão geral', 'M3 3h7v9H3z M14 3h7v5h-7z M14 12h7v9h-7z M3 16h7v5H3z'],
  ['h', 'Governança'],
  ['identidades', 'Identidades', 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M9 3a4 4 0 1 0 0 8a4 4 0 1 0 0-8 M22 21v-2a4 4 0 0 0-3-3.87 M16 3.13a4 4 0 0 1 0 7.75'],
  ['acessos', 'Inventário de acessos', 'M8 3L4 7l4 4 M4 7h16 M16 21l4-4-4-4 M20 17H4'],
  ['riscos', 'Inteligência e riscos', 'M12 2L2 7l10 5 10-5-10-5Z M2 17l10 5 10-5 M2 12l10 5 10-5'],
  ['privilegiados', 'Acesso privilegiado', 'M2 15.5a5.5 5.5 0 1 0 11 0a5.5 5.5 0 1 0-11 0 M21 2l-9.6 9.6 M15.5 7.5l3 3L22 7l-3-3'],
  ['ueba', 'UEBA', 'M22 12h-4l-3 9L9 3l-3 9H2'],
  ['h', 'Plataforma'],
  ['credenciais', 'Credenciais', 'M12 22v-5 M9 8V2 M15 8V2 M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z'],
  ['auditoria', 'Auditoria', 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z M14 2v6h6 M9 14.5a2.5 2.5 0 1 0 5 0a2.5 2.5 0 1 0-5 0 M13.3 16.3L15 18'],
  ['compliance', 'Compliance', 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10 M9 12l2 2 4-4'],
  ['administracao', 'Administração', 'M21 4h-7 M10 4H3 M21 12h-9 M8 12H3 M21 20h-5 M12 20H3 M14 2v4 M8 10v4 M16 18v4'],
];
const PAGES = {
  dashboard: { crumb: ['Visão geral', 'Postura de acesso'], search: true, bell: true, add: true, load: () => loadDashboard() },
  identidades: { crumb: ['Governança', 'Identidades'], add: true, load: () => loadIdentities() },
  acessos: { crumb: ['Governança', 'Inventário de acessos'], add: true, load: () => loadAccesses() },
  riscos: { crumb: ['Governança', 'Inteligência e riscos'], add: true, load: () => loadRisks() },
  privilegiados: { crumb: ['Governança', 'Acesso privilegiado'], add: true, load: () => loadPrivileged() },
  ueba: { crumb: ['Governança', 'UEBA'], add: true, load: () => loadUeba() },
  credenciais: { crumb: ['Plataforma', 'Credenciais de acesso'], search: true, load: () => loadCredentials() },
  auditoria: { crumb: ['Plataforma', 'Auditoria'], add: true, load: () => loadAudit(), roles: ['admin', 'analyst', 'auditor'] },
  compliance: { crumb: ['Plataforma', 'Compliance'], add: true, load: () => loadCompliance() },
  administracao: { crumb: ['Plataforma', 'Administração'], add: true, load: () => loadAdmin(), roles: ['admin'] },
};
const LEVEL = { critical: 'Crítico', high: 'Alto', medium: 'Médio', low: 'Baixo' };
const ROLE_LABEL = { admin: 'Administrador', analyst: 'Analista', auditor: 'Auditor', reader: 'Leitor' };
const TYPE_LABEL = { user: 'Humana', service: 'Serviço', group: 'Grupo', public: 'Público' };
const RESOURCE_LABEL = { project: 'Projeto', account: 'Conta', subscription: 'Assinatura', repository: 'Repositório', resource: 'Recurso' };
const SCOPE_KIND = { GCP: 'Projeto', AWS: 'Conta', Azure: 'Assinatura' };
const STATUS_LABEL = { open: 'Aberto', remediating: 'Em remediação', accepted: 'Risco aceito', incident: 'Incidente aberto', dismissed: 'Descartado' };
const STATUS_CLASS = { open: 'tag tag-accent', remediating: 'tag tag-outline', accepted: 'tag tag-neutral', incident: 'tag tag-accent', dismissed: 'tag tag-neutral' };
const PAGE_SIZE = 50;
const pages = {};
const EXPIRY_WARNING_DAYS = 15;
const MAX_SCOPE_TAGS = 8;
const ICON = {
  plus: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"><path d="M12 5v14M5 12h14"></path></svg>',
  arrow: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6"></path></svg>',
  close: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"></path></svg>',
  check: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"><path d="M20 6 9 17l-5-5"></path></svg>',
  cross: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"></path></svg>',
};

/* ── helpers ────────────────────────────────────────────────────────── */
async function api(path, options = {}) {
  const response = await fetch(`/api${path}`, { headers: { 'Content-Type': 'application/json', ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}), ...(options.headers || {}) }, ...options });
  if (response.status === 204) return null;
  const body = await response.json().catch(() => ({ detail: 'Resposta inválida do servidor' }));
  if (response.status === 401 && path !== '/auth/login') { showLogin(); throw new Error('Sua sessão expirou. Entre novamente.'); }
  if (!response.ok) {
    const detail = typeof body.detail === 'string' ? body.detail : Array.isArray(body.detail) ? body.detail.map(item => item.msg).join(' ') : (body.detail?.errors || ['Não foi possível concluir a operação.']).join(' ');
    throw new Error(detail);
  }
  return body;
}
function escapeHtml(value) { return String(value ?? '').replace(/[&<>'"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c])); }
const fmt = value => Number(value || 0).toLocaleString('pt-BR');
const pct = (part, total) => total ? Math.round(part / total * 100) : 0;
function formatDate(value) { if (!value || value === 'Nunca') return 'Nunca'; const date = new Date(value); return Number.isNaN(date.getTime()) ? '—' : new Intl.DateTimeFormat('pt-BR', { dateStyle: 'short', timeStyle: 'short' }).format(date); }
function dayMonth(value) { const date = new Date(value); return `${String(date.getDate()).padStart(2, '0')}/${String(date.getMonth() + 1).padStart(2, '0')}`; }
function hourMinute(value) { const date = new Date(value); return Number.isNaN(date.getTime()) ? '—' : `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`; }
function age(value, prefix = '') {
  if (!value) return '—';
  const minutes = Math.max(0, Math.round((Date.now() - new Date(value)) / 60000));
  if (minutes < 60) return `${prefix}${minutes} min`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${prefix}${hours} h`;
  return `${prefix}${Math.round(hours / 24)} d`;
}
const ago = value => value ? age(value, 'há ') : '—';
const daysUntil = value => value ? Math.ceil((new Date(value) - Date.now()) / 86400000) : null;
const riskColor = value => value >= 85 ? 'var(--color-accent-700)' : value >= 70 ? 'var(--color-accent-500)' : value >= 40 ? 'var(--color-accent-300)' : 'var(--color-neutral-400)';
const levelOf = value => value >= 85 ? 'critical' : value >= 70 ? 'high' : value >= 40 ? 'medium' : 'low';
const sevTag = severity => `<span class="sev sev-${escapeHtml(severity)}">${LEVEL[severity] || escapeHtml(severity)}</span>`;
const bar = (width, color = '', cls = '') => `<div class="bar ${cls}"><span data-w="${Math.max(0, Math.min(100, width))}%"${color ? ` data-bg="${color}"` : ''}></span></div>`;
const isReadonly = () => ['auditor', 'reader'].includes(state.user?.role);
const stat = (label, value, sub, alertValue = false, extra = '') => `<div class="stat"${extra}><div class="stat-label">${escapeHtml(label)}</div><div class="stat-value${alertValue ? ' alert-value' : ''}">${escapeHtml(value)}</div><div class="stat-sub">${sub}</div></div>`;
const emptyRow = (cols, text) => `<tr class="empty-row"><td colspan="${cols}">${escapeHtml(text)}</td></tr>`;

// Columns flagged with `show: false` are dropped: a column the provider never fills is noise, not information.
function tableHTML(cls, columns, rows, rowAttrs, emptyText) {
  const cols = columns.filter(c => c.show !== false);
  return `<table class="table ${cls}"><thead><tr>${cols.map(c => `<th${c.right ? ' class="right"' : ''}>${c.head}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr${rowAttrs ? rowAttrs(r) : ''}>${cols.map(c => c.cell(r)).join('')}</tr>`).join('') || emptyRow(cols.length, emptyText)}</tbody></table>`;
}
// Pagination keeps long inventories at a normal page height; it resets when the filters (signature) change.
function pageOf(key, rows, signature) {
  const current = pages[key] || { index: 0, signature };
  if (current.signature !== signature) current.index = 0;
  current.signature = signature;
  current.index = Math.min(current.index, Math.max(0, Math.ceil(rows.length / PAGE_SIZE) - 1));
  pages[key] = current;
  return rows.slice(current.index * PAGE_SIZE, (current.index + 1) * PAGE_SIZE);
}
function pagerHTML(key, total, extra = '') {
  const index = pages[key]?.index || 0; const start = index * PAGE_SIZE; const end = Math.min(total, start + PAGE_SIZE);
  const note = extra ? `<span class="count-text">${escapeHtml(extra)}</span>` : '';
  if (total <= PAGE_SIZE) return `<div class="pager"><span class="count-text">${fmt(total)} registro(s)</span>${note}</div>`;
  return `<div class="pager"><span class="count-text num">${fmt(start + 1)}–${fmt(end)} de ${fmt(total)}</span><button type="button" class="btn btn-secondary btn-sm" data-pager="${key}" data-step="-1"${index === 0 ? ' disabled' : ''}>← Anterior</button><button type="button" class="btn btn-secondary btn-sm" data-pager="${key}" data-step="1"${end >= total ? ' disabled' : ''}>Próxima →</button>${note}</div>`;
}
function hiddenNote(labels) { return labels.length ? `Colunas ocultas por falta de dados do provedor: ${labels.join(', ')}.` : ''; }
function paint(root = document) {
  root.querySelectorAll('[data-flex],[data-w],[data-h],[data-bg],[data-left],[data-top],[data-cols]').forEach(el => {
    const d = el.dataset;
    if (d.flex) el.style.flex = d.flex;
    if (d.w) el.style.width = d.w;
    if (d.h) el.style.height = d.h;
    if (d.bg) el.style.background = d.bg;
    if (d.left) el.style.left = d.left;
    if (d.top) el.style.top = d.top;
    if (d.cols) el.style.gridTemplateColumns = d.cols;
  });
}
function setHTML(target, html) { const el = typeof target === 'string' ? $(target) : target; el.innerHTML = html; paint(el); return el; }
let toastTimer;
function toast(message, duration = 2600) { const el = $('#toast'); clearTimeout(toastTimer); el.textContent = message; el.classList.add('show'); toastTimer = setTimeout(() => el.classList.remove('show'), duration); }
function downloadCsv(filename, header, rows) {
  const csv = [header, ...rows].map(row => row.map(value => `"${String(value ?? '').replaceAll('"', '""')}"`).join(',')).join('\n');
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([`﻿${csv}`], { type: 'text/csv;charset=utf-8' }));
  link.download = filename; link.click(); URL.revokeObjectURL(link.href);
}
function confirmDialog({ title, text, ok, onConfirm }) {
  $('#confirm-title').textContent = title; $('#confirm-text').textContent = text;
  const button = $('#confirm-ok'); button.textContent = ok; button.disabled = false;
  button.onclick = async () => { button.disabled = true; try { await onConfirm(); $('#confirm-modal').close(); } catch (error) { toast(error.message); } finally { button.disabled = false; } };
  $('#confirm-modal').showModal();
}
function justifyDialog({ title, text, ok, onConfirm }) {
  $('#justify-title').textContent = title; $('#justify-text').textContent = text; $('#justify-input').value = '';
  const error = $('#justify-error'); error.hidden = true;
  const button = $('#justify-ok'); button.textContent = ok; button.disabled = false;
  button.onclick = async () => {
    const justification = $('#justify-input').value.trim();
    if (justification.length < 3) { error.textContent = 'Informe a justificativa (mínimo de 3 caracteres).'; error.hidden = false; return; }
    button.disabled = true;
    try { await onConfirm(justification); $('#justify-modal').close(); } catch (failure) { error.textContent = failure.message; error.hidden = false; } finally { button.disabled = false; }
  };
  $('#justify-modal').showModal(); $('#justify-input').focus();
}

/* ── shell: sidebar, navigation, topbar ─────────────────────────────── */
function canSee(page) { const roles = PAGES[page]?.roles; return !roles || roles.includes(state.user?.role); }
function renderSidebar() {
  setHTML('#sb-nav', NAV.map(([key, label, icon]) => key === 'h'
    ? `<div class="sb-head">${label}</div>`
    : canSee(key) ? `<button type="button" class="sb-link" data-nav="${key}"${key === state.page ? ' aria-current="page"' : ''}><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${icon}"></path></svg>${label}</button>` : '').join(''));
}
function renderStatus() {
  const s = state.status;
  if (!s) return;
  $('#sb-dot').classList.toggle('idle', !s.integrations);
  $('#sb-status-text').textContent = s.integrations ? `Monitoramento ativo · ${s.integrations} integraç${s.integrations > 1 ? 'ões' : 'ão'}` : 'Monitoramento não iniciado';
  $('#sb-status-sub').textContent = s.lastAnalysisAt ? `Última análise ${formatDate(s.lastAnalysisAt)}` : 'Nenhuma análise executada';
  $('#alerts-dot').hidden = !(s.criticalOpen || s.attention);
  $('#alerts-btn').setAttribute('aria-label', `Alertas: ${s.criticalOpen} risco(s) crítico(s), ${s.attention} credencial(is) com atenção`);
}
async function loadStatus() { try { state.status = await api('/platform/status'); renderStatus(); } catch { /* sidebar keeps the previous status */ } }
function closeDrawer() { $('#sidebar').classList.remove('open'); $('#scrim').classList.remove('open'); }
function navigate(page, options = {}) {
  if (!PAGES[page] || !canSee(page)) page = 'dashboard';
  state.page = page;
  $$('.page').forEach(section => section.classList.toggle('active', section.id === page));
  document.body.dataset.page = page;
  const meta = PAGES[page];
  $('#crumb-section').textContent = meta.crumb[0]; $('#crumb-page').textContent = meta.crumb[1];
  $('#global-search').hidden = !meta.search; $('#alerts-btn').hidden = !meta.bell;
  $('#new-credential-top').hidden = !meta.add || isReadonly();
  renderSidebar(); closeDrawer();
  window.scrollTo({ top: 0 });
  if (options.apply) options.apply();
  meta.load();
}
function refreshCurrent() { PAGES[state.page]?.load(); loadStatus(); }

/* ══ Visão geral ═════════════════════════════════════════════════════ */
async function loadDashboard() {
  const d = state.dash;
  const query = new URLSearchParams({ period: d.period });
  if (d.credentialId) query.set('credential_id', d.credentialId);
  if (d.provider) query.set('provider', d.provider);
  try { d.data = await api(`/dashboard/overview?${query}`); renderDashboard(); } catch (error) { setHTML('#dash-body', `<div class="empty">Não foi possível carregar a visão geral: ${escapeHtml(error.message)}</div>`); }
}
function renderDashboard() {
  const d = state.dash.data; const s = state.dash;
  const select = $('#dash-env');
  select.innerHTML = '<option value="all">Todos os domínios e ambientes</option>' + d.credentials.map(c => `<option value="${c.id}">${escapeHtml(c.provider)} · ${escapeHtml(c.name)}</option>`).join('');
  select.value = s.credentialId ? String(s.credentialId) : 'all';
  $$('input[name="dash-period"]').forEach(radio => { radio.checked = Number(radio.value) === s.period; });
  const sev = d.severities; const total = d.total;
  $('#dash-summary').textContent = d.assessed
    ? `${fmt(total)} riscos ativos em ${d.environmentCount} ambiente(s) de ${d.providerCount} provedor(es) · ${fmt(sev.critical)} críticos exigem avaliação imediata.`
    : 'Nenhuma análise concluída. Conecte uma credencial e execute a análise para medir a postura de acesso.';
  const selected = d.credentials.find(c => c.id === s.credentialId);
  const scopeName = selected ? selected.name : s.provider;
  const score = d.score;
  const trend = d.trend; const first = trend[0]?.risk; const last = trend.at(-1)?.risk;
  const delta = trend.length > 1 ? last - first : null;
  const periodLabel = `${d.period} dias`;
  const scoreText = !d.assessed ? 'Quanto maior, pior. Execute a primeira análise para calcular a nota.'
    : `Quanto maior, pior. ${delta === null ? 'Primeira medição no período' : delta === 0 ? `Estável em ${periodLabel}` : `${delta > 0 ? 'Piorou' : 'Melhorou'} ${Math.abs(delta)} pts em ${periodLabel}`}, com ${fmt(sev.critical)} risco(s) crítico(s) e ${fmt(d.orphanAccounts)} conta(s) órfã(s).`;
  const level = d.level || 'low';
  const sevRows = [['critical', 'Crítico', 'var(--color-accent-700)'], ['high', 'Alto', 'var(--color-accent-500)'], ['medium', 'Médio', 'var(--color-accent-300)'], ['low', 'Baixo', 'var(--color-neutral-400)']];
  const providerCards = d.providers.map(p => {
    const active = s.provider === p.provider; const faded = (s.provider && !active) || (selected && selected.provider !== p.provider);
    return `<button type="button" class="prov-card${active ? ' active' : ''}${faded ? ' faded' : ''}" data-provider="${p.provider}"><div class="prov-top"><span class="prov-name">${p.provider} <span>${p.environments} ambiente(s)</span></span><span class="prov-score">${p.score ?? '—'}</span></div>${bar(p.score ?? 0, riskColor(p.score ?? 0))}<div class="muted-sm">${fmt(p.risks)} riscos · ${fmt(p.critical)} críticos · ${fmt(p.identities)} identidades</div></button>`;
  }).join('') || '<div class="empty">Nenhum provedor conectado.</div>';
  const k = d.kpis;
  const deltaOf = (now, before) => before === null || before === undefined ? '' : `${now - before > 0 ? '+' : now - before < 0 ? '−' : ''}${fmt(Math.abs(now - before))}`;
  const kpi = (label, value, deltaText, sub, accent = false) => `<div class="stat"><div class="stat-label">${label}</div><div class="stat-value">${value}</div><div class="stat-delta">${deltaText ? `<b class="${accent ? 'accent-text' : ''}">${escapeHtml(deltaText)}</b>` : ''}<span class="muted">${sub}</span></div></div>`;
  const maxRule = Math.max(1, ...d.rules.map(r => r.count));
  const providers = d.providers.map(p => p.provider);
  const heatMax = Math.max(1, ...d.heatmap.flatMap(row => providers.map(name => row.cells[name] || 0)));
  const dimProvider = name => (s.provider && s.provider !== name) || (selected && selected.provider !== name);
  const heat = providers.length ? `<div class="heat" data-cols="minmax(0,1fr) repeat(${providers.length},64px)"><span></span>${providers.map(name => `<span class="heat-head${dimProvider(name) ? ' dim' : ''}">${name}</span>`).join('')}${d.heatmap.map(row => `<span class="heat-name">${escapeHtml(row.module)}</span>${providers.map(name => { const v = row.cells[name] || 0; const lvl = v ? Math.min(4, Math.ceil(v / heatMax * 4)) : 0; return `<span class="heat-cell heat-${lvl}${dimProvider(name) ? ' dim' : ''}" title="${v} achado(s) abertos">${fmt(v)}</span>`; }).join('')}`).join('')}</div><div class="note">Achados abertos por módulo e provedor.</div>` : '<div class="empty">Conecte um provedor para formar o mapa.</div>';
  const envRows = d.environments.map(e => `<tr class="clickable" data-open-project="${e.credentialId}" data-resource="${escapeHtml(e.resourceId)}"><td><div class="semibold">${escapeHtml(e.name)}</div><div class="t-sub">${RESOURCE_LABEL[e.type] || escapeHtml(e.type)}</div></td><td>${escapeHtml(e.provider)}</td><td class="right num">${fmt(e.identities)}</td><td class="right num"><span class="strong accent-text">${e.critical}</span> / ${e.high}</td><td><div class="score-cell"><b>${e.score}</b>${bar(e.score, riskColor(e.score))}</div></td><td><span class="tag ${e.attention ? 'tag-accent' : 'tag-neutral'}">${escapeHtml(e.status)}</span></td></tr>`).join('') || emptyRow(6, 'Nenhum projeto, conta ou assinatura analisado.');
  const priorities = d.priorities.map(r => `<div class="risk-row">${sevTag(r.severity)}<div class="ellipsis-wrap"><div class="title">${escapeHtml(r.title)}</div><div class="muted-sm ellipsis">${escapeHtml(r.rule)} · ${escapeHtml(r.who)} · ${escapeHtml(r.where)}</div></div><span class="muted-sm num">${age(r.firstSeen)}</span></div>`).join('') || '<div class="empty">Nenhum risco aberto.</div>';
  const ueba = d.ueba.map(u => `<div class="ueba-mini"><b>${hourMinute(u.time)}</b><div><div class="semibold">${escapeHtml(u.title)}</div><div class="muted-sm">${escapeHtml(u.who)} · ${escapeHtml(u.provider)} · ${escapeHtml(u.category)}</div></div></div>`).join('') || '<div class="empty">Nenhuma anomalia nos logs coletados.</div>';
  const frameworks = d.frameworks.map(f => `<div class="fw-row"><div class="fw-row-top"><span class="semibold">${escapeHtml(f.name)}</span><span class="strong num">${d.assessed ? `${f.percent}%` : '—'}</span></div>${bar(d.assessed ? f.percent : 0, '', 'bar-8')}<div class="muted-sm">${f.met} de ${f.total} controles atendidos</div></div>`).join('');
  const chart = renderTrendChart(trend, score);
  setHTML('#dash-body', `
    <div class="band top">
      <section class="cell" data-flex="1.15 1 340px">
        <div class="cell-head"><div><div class="card-kicker">Nota de risco</div><div class="card-title">${scopeName ? `Risco · ${escapeHtml(scopeName)}` : 'Risco consolidado'}</div></div><span class="tag tag-neutral">${d.lastAnalysisAt ? `Última análise · ${hourMinute(d.lastAnalysisAt)}` : 'Sem análise'}</span></div>
        <div class="score-row"><div class="score-big">${score ?? '—'}</div><div class="score-side"><span class="muted">/100</span>${score !== null ? `<span class="level-tag sev-${level}">Risco ${LEVEL[level]}</span>` : ''}</div></div>
        <div class="stack-6"><div class="gauge"><div class="gauge-bands"><span></span><span></span><span></span><span></span></div>${score !== null ? `<div class="gauge-marker" data-left="${score}%"></div>` : ''}</div><div class="gauge-labels"><span>Baixo</span><span>Médio</span><span>Alto</span><span>Crítico</span></div></div>
        <div class="score-text">${escapeHtml(scoreText)}</div>
        <div class="btn-row push-bottom"><button type="button" class="btn btn-primary" data-go-risk="critical">Tratar riscos críticos${ICON.arrow}</button><button type="button" class="btn btn-secondary mutating" data-new-review="privileged">Iniciar Access Review</button></div>
      </section>
      <section class="cell gap-16" data-flex="1 1 300px">
        <div><div class="card-kicker">Severidade</div><div class="card-title">Distribuição de risco</div></div>
        <div class="sev-stack">${total ? sevRows.map(([key, , color]) => `<span data-w="${sev[key] / total * 100}%" data-bg="${color}"></span>`).join('') : '<span data-w="100%" data-bg="var(--color-neutral-200)"></span>'}</div>
        <div>${sevRows.map(([key, name, color]) => `<div class="legend-row"><span class="swatch" data-bg="${color}"></span><span>${name}</span><span class="strong num">${fmt(sev[key])}</span><span class="pct">${pct(sev[key], total)}%</span></div>`).join('')}</div>
        <div class="total-row"><b>${fmt(total)}</b><span>riscos ativos · ${fmt(d.newRisks)} novos no período</span></div>
      </section>
      <section class="cell gap-12" data-flex="1 1 300px">
        <div class="cell-head"><div><div class="card-kicker">Ambiente</div><div class="card-title">Risco por provedor</div></div><span class="muted-sm">Clique para filtrar</span></div>
        ${providerCards}
      </section>
    </div>
    <div class="band stats">
      ${kpi('Identidades', fmt(k.identities), deltaOf(k.identities, k.identitiesBefore), 'inventário normalizado')}
      ${kpi('Acessos', fmt(k.accesses), deltaOf(k.accesses, k.accessesBefore), 'concessões analisadas')}
      ${kpi('Acessos privilegiados', fmt(k.privileged), '', 'funções de alto impacto')}
      ${kpi('Contas órfãs', fmt(k.orphanAccounts), '', 'sem dono ativo')}
      ${kpi('Anomalias UEBA', fmt(k.anomalies24h), '24 h', 'comportamento atípico')}
      ${kpi('Conformidade', k.compliance === null ? '—' : `${k.compliance}%`, '', 'controles atendidos')}
    </div>
    <div class="band">
      <section class="cell gap-16" data-flex="1.7 1 520px">
        <div class="cell-head"><div><div class="card-kicker">Evolução</div><div class="card-title">Tendência da nota de risco</div></div><div class="btn-row"><span class="target-legend"><i></i>Meta ≤ 50</span>${delta !== null ? `<span class="tag tag-accent semibold">${delta > 0 ? '+' : ''}${delta} pts em ${periodLabel} · ${delta > 0 ? 'piora' : delta < 0 ? 'melhora' : 'estável'}</span>` : ''}</div></div>
        ${chart}
      </section>
      <section class="cell gap-12" data-flex="1 1 340px">
        <div><div class="card-kicker">Regras de validação</div><div class="card-title">Achados por regra</div></div>
        <div>${d.rules.map(r => `<button type="button" class="rule-row" data-go-rule="${r.code}"><span class="rule-name">${escapeHtml(r.name)}</span><span class="rule-n">${fmt(r.count)}</span>${bar(r.count / maxRule * 100, '', 'bar-4 full')}</button>`).join('')}</div>
      </section>
    </div>
    <div class="band">
      <section class="cell" data-flex="1 1 360px"><div><div class="card-kicker">Mapa de calor</div><div class="card-title">Risco por módulo × provedor</div></div>${heat}</section>
      <section class="cell" data-flex="2 1 560px">
        <div class="cell-head"><div><div class="card-kicker">Risco do ambiente</div><div class="card-title">Contas, projetos e florestas analisados</div></div><button type="button" class="btn btn-ghost" data-nav="credenciais">Gerenciar credenciais →</button></div>
        <div class="table-wrap"><table class="table min-640"><thead><tr><th>Ambiente</th><th>Provedor</th><th class="right">Identidades</th><th class="right">Crít. / Alto</th><th>Nota</th><th>Status</th></tr></thead><tbody>${envRows}</tbody></table></div>
        ${d.environmentTotal > d.environments.length ? `<div class="foot-text">Exibindo os ${d.environments.length} ambientes de maior risco de ${fmt(d.environmentTotal)}.</div>` : ''}
      </section>
    </div>
    <div class="band">
      <section class="cell gap-6" data-flex="1.6 1 460px"><div class="cell-head"><div><div class="card-kicker">Access Risk</div><div class="card-title">Riscos prioritários</div></div><button type="button" class="btn btn-ghost" data-nav="riscos">Ver todos →</button></div>${priorities}</section>
      <section class="cell gap-6" data-flex="1 1 300px"><div><div class="card-kicker">UEBA</div><div class="card-title">Anomalias recentes</div></div>${ueba}</section>
      <section class="cell" data-flex="1 1 280px"><div><div class="card-kicker">Compliance Audit</div><div class="card-title">Controles atendidos</div></div>${frameworks}</section>
    </div>`);
}
function renderTrendChart(trend, score) {
  if (!trend.length) return '<div class="chart-empty">Execute análises para formar o histórico da nota.</div>';
  const n = trend.length;
  const xs = trend.map((_, i) => n === 1 ? 600 : i / (n - 1) * 600);
  const ys = trend.map(p => 200 - p.risk * 2);
  const line = xs.map((x, i) => `${i ? 'L' : 'M'}${x.toFixed(1)} ${ys[i].toFixed(1)}`).join(' ');
  const labelEvery = Math.max(1, Math.ceil(n / 7));
  const labels = trend.filter((_, i) => i % labelEvery === 0 || i === n - 1).map(p => `<span>${dayMonth(`${p.date}T12:00:00`)}</span>`).join('');
  const last = trend.at(-1).risk;
  return `<div class="chart"><div class="chart-y"><span>100</span><span>50</span><span>0</span></div><div class="chart-plot"><svg viewBox="0 0 600 200" preserveAspectRatio="none" aria-label="Evolução da nota de risco" role="img"><line x1="0" y1="0" x2="600" y2="0" stroke="var(--color-neutral-300)" stroke-width="1" vector-effect="non-scaling-stroke"></line><line x1="0" y1="100" x2="600" y2="100" stroke="var(--color-neutral-600)" stroke-width="1.5" stroke-dasharray="5 4" vector-effect="non-scaling-stroke"></line><path d="${line} L${xs.at(-1)} 200 L${xs[0]} 200 Z" fill="var(--color-accent-100)"></path><path d="${line}" fill="none" stroke="var(--color-accent)" stroke-width="2.5" vector-effect="non-scaling-stroke"></path></svg>${trend.map((p, i) => `<div class="chart-pt" title="${dayMonth(`${p.date}T12:00:00`)}: ${p.risk}" data-left="${xs[i] / 6}%" data-top="${100 - p.risk}%"></div>`).join('')}<div class="chart-last" data-left="100%" data-top="${100 - last}%">${score ?? last}</div></div><div></div><div class="chart-x">${labels}</div></div>`;
}

/* ══ Identidades ═════════════════════════════════════════════════════ */
async function loadIdentities() {
  try {
    const [list, summary] = await Promise.all([api('/identities?limit=10000'), api('/identities/summary')]);
    Object.assign(state.ids, { list, summary });
    if (state.ids.selected && !list.some(item => item.id === state.ids.selected)) state.ids.selected = null;
    renderIdentities();
    const first = filteredIdentities()[0];
    if (!state.ids.selected && first) selectIdentity(first.id); else if (state.ids.selected) selectIdentity(state.ids.selected);
  } catch (error) { toast(`Identidades indisponíveis: ${error.message}`); }
}
function filteredIdentities() {
  const { list, type, provider, q } = state.ids; const query = q.trim().toLowerCase();
  return list.filter(item => (type === 'all' || (type === 'orphan' ? item.orphan : type === 'leaver' ? item.lifecycleStatus === 'leaver' : item.type === type))
    && (provider === 'all' || item.provider === provider)
    && (!query || `${item.name} ${item.email || ''} ${item.externalId} ${item.environment}`.toLowerCase().includes(query)));
}
function lifecycleTag(item) {
  if (item.orphan) return '<span class="tag tag-accent">Órfã</span>';
  if (item.lifecycleStatus === 'leaver') return '<span class="tag tag-accent">Desligada</span>';
  if (item.lifecycleStatus === 'mover') return '<span class="tag tag-outline">Movimentação</span>';
  if (!item.enabled) return '<span class="tag tag-neutral">Desabilitada</span>';
  return '<span class="tag tag-neutral">Ativa</span>';
}
function renderIdentities() {
  const s = state.ids.summary; const rows = filteredIdentities(); const shown = pageOf('ids', rows, `${state.ids.type}|${state.ids.provider}|${state.ids.q}`);
  setHTML('#id-kpis', [
    stat('Identidades', fmt(s.total), 'inventário normalizado'),
    stat('Humanas', fmt(s.humans), `${pct(s.humans, s.total)}% do inventário`),
    stat('De serviço', fmt(s.services), 'service accounts, roles, apps'),
    stat('Órfãs', fmt(s.orphan), 'sem responsável ativo', true),
    s.mfaKnown ? stat('Sem MFA', fmt(s.noMfa), `de ${fmt(s.mfaKnown)} humanas com MFA informado`, true) : stat('Sem MFA', '—', 'MFA não informado pelo provedor'),
    s.lastSeenKnown ? stat('Inativas > 90 dias', fmt(s.inactive90), `de ${fmt(s.lastSeenKnown)} com último login conhecido`) : stat('Inativas > 90 dias', '—', 'último login não informado'),
  ].join(''));
  $('#id-count').textContent = `${fmt(rows.length)} de ${fmt(s.total)} identidades`;
  const seen = state.ids.list.some(item => item.lastSeenAt);
  const multiProvider = new Set(state.ids.list.map(item => item.provider)).size > 1;
  const multiEnvironment = new Set(state.ids.list.map(item => item.environment)).size > 1;
  setHTML('#id-table', tableHTML('', [
    { head: 'Identidade', cell: item => `<td><div class="semibold break">${escapeHtml(item.name)}</div>${(item.email || item.externalId) !== item.name ? `<div class="t-sub break">${escapeHtml(item.email || item.externalId)}</div>` : ''}</td>` },
    { head: 'Tipo', cell: item => `<td>${TYPE_LABEL[item.type] || escapeHtml(item.type)}</td>` },
    { head: 'Provedor', show: multiProvider, cell: item => `<td><span class="tag tag-neutral">${escapeHtml(item.provider)}</span></td>` },
    { head: 'Ambiente', show: multiEnvironment, cell: item => `<td>${escapeHtml(item.environment)}</td>` },
    { head: 'Acessos', right: true, cell: item => `<td class="right num">${fmt(item.accessCount)}</td>` },
    { head: 'Risco', cell: item => `<td><div class="score-cell"><b>${item.riskScore}</b>${bar(item.riskScore, riskColor(item.riskScore))}</div></td>` },
    { head: 'Ciclo de vida', cell: item => `<td>${lifecycleTag(item)}</td>` },
    { head: 'Último login', show: seen, cell: item => `<td class="muted nowrap">${ago(item.lastSeenAt)}</td>` },
  ], shown, item => ` class="clickable${item.id === state.ids.selected ? ' selected' : ''}" data-identity="${item.id}"`, state.ids.list.length ? 'Nenhuma identidade corresponde aos filtros.' : 'Execute uma análise para preencher o inventário.'));
  setHTML('#id-foot', pagerHTML('ids', rows.length));
}
async function selectIdentity(id) {
  state.ids.selected = id;
  $$('#id-table tr[data-identity]').forEach(row => row.classList.toggle('selected', Number(row.dataset.identity) === id));
  const aside = $('#id-aside'); aside.hidden = false;
  setHTML(aside, '<div class="muted">Carregando identidade…</div>');
  try {
    const d = await api(`/identities/${id}`); state.ids.detail = d;
    if (state.ids.selected !== id) return;
    const mfa = d.mfaEnabled === true ? 'Ativo' : d.mfaEnabled === false ? 'Não configurado' : 'Não informado pelo provedor';
    const lifecycle = { leaver: 'Desligada', mover: 'Movimentação', active: 'Ativa' }[d.lifecycleStatus] || (d.lifecycleStatus ? escapeHtml(d.lifecycleStatus) : 'Não informado');
    const kind = d.type === 'user' ? 'Identidade humana' : d.type === 'service' ? 'Identidade de serviço' : `Identidade · ${TYPE_LABEL[d.type] || d.type}`;
    setHTML(aside, `
      <div class="dialog-head"><div class="break"><div class="card-kicker">${escapeHtml(kind)}</div><div class="aside-title">${escapeHtml(d.name)}</div>${(d.email || d.externalId) !== d.name ? `<div class="muted-sm break">${escapeHtml(d.email || d.externalId)}</div>` : ''}</div><button type="button" class="btn btn-icon" aria-label="Fechar" data-close-aside="id">${ICON.close}</button></div>
      <div class="big-score"><b>${d.riskScore}</b><span>nota de risco · ${LEVEL[levelOf(d.riskScore)].toLowerCase()}</span></div>
      <div class="kv"><span>Ambiente</span><span>${escapeHtml(d.environment)} · ${escapeHtml(d.provider)}</span><span>Responsável</span><span>${escapeHtml(d.owner || 'Não informado pelo provedor')}</span><span>Ciclo de vida</span><span>${lifecycle}</span><span>MFA</span><span>${mfa}</span><span>Acessos</span><span>${fmt(d.accesses.length)} concessões · ${fmt(d.privilegedCount)} privilegiadas</span><span>Último login</span><span>${d.lastSeenAt ? formatDate(d.lastSeenAt) : 'Não informado'}</span></div>
      <div class="stack-6"><div class="overline">Sinais de risco</div>${d.findings.map(f => `<div class="flag" title="${escapeHtml(f.description)}">${escapeHtml(f.title)}</div>`).join('') || '<div class="muted">Nenhum sinal de risco ativo.</div>'}</div>
      <div class="stack-6 push-bottom"><button type="button" class="btn btn-primary btn-block" data-identity-accesses="${escapeHtml(d.externalId)}">Ver acessos desta identidade</button><button type="button" class="btn btn-secondary btn-block mutating" data-new-review="identity" data-identity-id="${d.id}" data-identity-name="${escapeHtml(d.name)}">Solicitar revisão ao responsável</button></div>`);
  } catch (error) { setHTML(aside, `<div class="alert">${escapeHtml(error.message)}</div>`); }
}

/* ══ Inventário de acessos ═══════════════════════════════════════════ */
async function loadAccesses() {
  try {
    const [grants, summary] = await Promise.all([api('/accesses?limit=20000'), api('/accesses/summary')]);
    Object.assign(state.acc, { grants, summary, projects: null, roles: null, accounts: null });
    if (state.acc.view !== 'grants') await loadAccessView();
    renderAccesses();
  } catch (error) { toast(`Inventário indisponível: ${error.message}`); }
}
async function loadAccessView() {
  const a = state.acc;
  if (a.view === 'projects' && !a.projects) a.projects = await api('/inventory/projects?limit=10000');
  if (a.view === 'roles' && !a.roles) a.roles = await api('/inventory/roles?limit=10000');
  if (a.view === 'accounts' && !a.accounts) a.accounts = await api('/inventory/accounts?limit=10000');
}
function isStale(grant) { const days = grant.lastUsedAt ? (Date.now() - new Date(grant.lastUsedAt)) / 86400000 : null; return (days !== null && days > state.acc.summary.unusedDays) || (grant.totalPermissions > 0 && grant.usedPermissions === 0); }
function usageCell(g) { return g.totalPermissions ? `<div class="stack-6">${bar(g.usedPermissions / g.totalPermissions * 100, g.usedPermissions ? '' : 'var(--color-accent)')}<span class="muted-sm">${fmt(g.usedPermissions)} de ${fmt(g.totalPermissions)} (${pct(g.usedPermissions, g.totalPermissions)}%)</span></div>` : '<span class="muted-sm">Sem telemetria</span>'; }
function accessMatches(text) { const query = state.acc.q.trim().toLowerCase(); return !query || text.toLowerCase().includes(query); }
function renderAccesses() {
  const a = state.acc; const s = a.summary;
  $('#acc-unused-text').textContent = `Somente sem uso há mais de ${s.unusedDays} dias`;
  $('#acc-unused-label').hidden = a.view !== 'grants';
  $('#acc-unused').disabled = !s.withUsage; if (!s.withUsage) { $('#acc-unused').checked = false; a.unused = false; }
  $('#acc-unused-label').title = s.withUsage ? '' : 'Disponível quando o provedor fornecer dados de uso';
  setHTML('#acc-kpis', [
    stat('Concessões', fmt(s.total), `em ${fmt(state.credentials.length || new Set(a.grants.map(g => g.credentialId)).size)} ambiente(s)`),
    stat('Recursos', fmt(s.resources), 'projetos, contas, assinaturas e repositórios'),
    s.withUsage ? stat(`Sem uso > ${s.unusedDays} dias`, fmt(s.unused), `${pct(s.unused, s.withUsage)}% das ${fmt(s.withUsage)} com telemetria de uso`, true) : stat(`Sem uso > ${s.unusedDays} dias`, '—', 'sem dados de uso dos provedores'),
    stat('Concessões diretas', fmt(s.direct), 'fora de grupos'),
    stat('Curingas (*)', fmt(s.wildcard), 'permissões irrestritas', true),
  ].join(''));
  const providerOk = provider => a.prov === 'all' || provider === a.prov;
  let table = ''; let total = 0; let shownCount = 0; let note = '';
  const multiEnv = new Set(a.grants.map(g => g.credentialId)).size > 1;
  if (a.view === 'grants') {
    const rows = a.grants.filter(g => providerOk(g.provider) && (!a.unused || isStale(g)) && accessMatches(`${g.identityName} ${g.identityId} ${g.resourceName} ${g.role}`));
    total = rows.length; const shown = pageOf('acc', rows, `${a.view}|${a.prov}|${a.unused}|${a.q}`); shownCount = shown.length;
    const has = { granted: a.grants.some(g => g.grantedAt), used: a.grants.some(g => g.lastUsedAt), usage: a.grants.some(g => g.totalPermissions) };
    note = hiddenNote([!has.granted && 'concedido', !has.used && 'último uso', !has.usage && 'permissões usadas'].filter(Boolean));
    table = tableHTML(has.usage || has.used ? 'min-900' : 'min-720', [
      { head: 'Identidade', cell: g => `<td><div class="semibold break">${escapeHtml(g.identityName)}</div><div class="t-sub">${TYPE_LABEL[g.identityType] || escapeHtml(g.identityType || 'Identidade')}</div></td>` },
      { head: 'Recurso', cell: g => `<td><div class="break">${escapeHtml(g.resourceName)}</div><div class="t-sub">${escapeHtml(g.provider)}${multiEnv ? ` · ${escapeHtml(g.environment)}` : ''}</div></td>` },
      { head: 'Papel / permissão', cell: g => `<td class="mono break">${escapeHtml(g.role)}</td>` },
      { head: 'Origem', cell: g => `<td>${escapeHtml(g.origin)}</td>` },
      { head: 'Nível', cell: g => `<td>${g.privileged ? '<span class="tag tag-accent">Privilegiado</span>' : '<span class="tag tag-neutral">Padrão</span>'}${g.wildcard ? ' <span class="tag tag-outline" title="Permissão irrestrita">*</span>' : ''}</td>` },
      { head: 'Concedido', show: has.granted, cell: g => `<td class="muted nowrap">${g.grantedAt ? `${dayMonth(g.grantedAt)}/${new Date(g.grantedAt).getFullYear()}` : '—'}</td>` },
      { head: 'Último uso', show: has.used, cell: g => `<td class="nowrap ${isStale(g) ? 'strong accent-text' : ''}">${g.lastUsedAt ? ago(g.lastUsedAt) : '<span class="muted">—</span>'}</td>` },
      { head: 'Permissões usadas', show: has.usage, cell: g => `<td>${g.totalPermissions ? usageCell(g) : '<span class="muted">—</span>'}</td>` },
    ], shown, g => isStale(g) ? ' class="stale"' : '', a.grants.length ? 'Nenhuma concessão corresponde aos filtros.' : 'Execute uma análise para preencher o inventário.');
  } else if (a.view === 'projects') {
    const rows = (a.projects || []).filter(p => providerOk(p.provider) && accessMatches(`${p.name} ${p.resourceId} ${p.environment}`));
    total = rows.length; const shown = pageOf('acc', rows, `${a.view}|${a.prov}|${a.unused}|${a.q}`); shownCount = shown.length;
    table = `<table class="table min-820"><thead><tr><th>Projeto / recurso</th>${multiEnv ? '<th>Ambiente</th>' : ''}<th>Tipo</th><th class="right">Identidades</th><th class="right">Concessões</th><th class="right">Privilegiadas</th><th>Riscos</th><th></th></tr></thead><tbody>${shown.map(p => `<tr><td><div class="semibold break">${escapeHtml(p.name)}</div><div class="t-sub break">${escapeHtml(p.resourceId)}</div></td>${multiEnv ? `<td>${escapeHtml(p.provider)} · ${escapeHtml(p.environment)}</td>` : ''}<td>${RESOURCE_LABEL[p.type] || escapeHtml(p.type)}</td><td class="right num">${fmt(p.identityCount)}</td><td class="right num">${fmt(p.accessCount)}</td><td class="right num">${fmt(p.privilegedCount)}</td><td>${p.findingCount ? `${sevTag(p.maxSeverity || 'medium')} <span class="num">${fmt(p.findingCount)}</span>` : '<span class="muted">Nenhum</span>'}</td><td class="right"><button type="button" class="btn btn-secondary btn-sm" data-open-project="${p.credentialId}" data-resource="${escapeHtml(p.resourceId)}">Abrir</button></td></tr>`).join('') || emptyRow(multiEnv ? 8 : 7, 'Nenhum projeto com concessões.')}</tbody></table>`;
  } else if (a.view === 'roles') {
    const rows = (a.roles || []).filter(r => providerOk(r.provider) && accessMatches(`${r.role} ${r.roleLabel} ${r.environment}`));
    total = rows.length; const shown = pageOf('acc', rows, `${a.view}|${a.prov}|${a.unused}|${a.q}`); shownCount = shown.length;
    table = `<table class="table min-900"><thead><tr><th>Papel</th>${multiEnv ? '<th>Ambiente</th>' : ''}<th>Capacidade efetiva</th><th class="right">Identidades</th><th class="right">Recursos</th><th class="right">Concessões</th><th class="right">Privilegiadas</th><th>Criticidade</th></tr></thead><tbody>${shown.map(r => `<tr><td><div class="semibold break">${escapeHtml(r.roleLabel)}</div>${r.roleLabel !== r.role ? `<div class="t-sub mono break">${escapeHtml(r.role)}</div>` : ''}</td>${multiEnv ? `<td>${escapeHtml(r.provider)} · ${escapeHtml(r.environment)}</td>` : ''}<td>${escapeHtml(r.capability)}</td><td class="right num">${fmt(r.identityCount)}</td><td class="right num">${fmt(r.resourceCount)}</td><td class="right num">${fmt(r.accessCount)}</td><td class="right num">${fmt(r.privilegedCount)}</td><td>${sevTag(r.severity)}</td></tr>`).join('') || emptyRow(multiEnv ? 8 : 7, 'Nenhum papel concedido.')}</tbody></table>`;
  } else {
    const rows = (a.accounts || []).filter(r => providerOk(r.provider) && accessMatches(`${r.name} ${r.externalId} ${r.email || ''}`));
    total = rows.length; const shown = pageOf('acc', rows, `${a.view}|${a.prov}|${a.unused}|${a.q}`); shownCount = shown.length;
    table = `<table class="table min-900"><thead><tr><th>Conta</th>${multiEnv ? '<th>Ambiente</th>' : ''}<th>Tipo</th><th>Estado</th><th class="right">Recursos</th><th class="right">Concessões</th><th class="right">Privilegiadas</th><th class="right">Riscos</th><th></th></tr></thead><tbody>${shown.map(r => `<tr><td><div class="semibold break">${escapeHtml(r.name)}</div><div class="t-sub break">${escapeHtml(r.externalId)}</div></td>${multiEnv ? `<td>${escapeHtml(r.provider)} · ${escapeHtml(r.environment)}</td>` : ''}<td>${TYPE_LABEL[r.type] || escapeHtml(r.type)}</td><td>${r.enabled ? 'Ativa' : 'Desabilitada'}</td><td class="right num">${fmt(r.resourceCount)}</td><td class="right num">${fmt(r.accessCount)}</td><td class="right num">${fmt(r.privilegedCount)}</td><td class="right num">${fmt(r.findingCount)}</td><td class="right"><button type="button" class="btn btn-secondary btn-sm" data-open-identity="${r.id}">Ver identidade</button></td></tr>`).join('') || emptyRow(multiEnv ? 9 : 8, 'Nenhuma conta coletada.')}</tbody></table>`;
  }
  setHTML('#acc-table', table);
  setHTML('#acc-foot', pagerHTML('acc', total, note));
}
async function openProject(credentialId, resourceId) {
  const modal = $('#project-modal'); const content = $('#project-content');
  $('#project-title').textContent = 'Carregando…'; setHTML(content, '<div class="muted">Carregando papéis e contas do projeto…</div>'); modal.showModal();
  try {
    const d = await api(`/inventory/project-detail?credential_id=${credentialId}&resource_id=${encodeURIComponent(resourceId)}`);
    $('#project-title').textContent = d.name;
    const renderRoles = () => setHTML(content, `<div class="kv"><span>Ambiente</span><span>${escapeHtml(d.environment)} · ${escapeHtml(d.provider)}</span><span>Identificador</span><span class="mono">${escapeHtml(d.resourceId)}</span><span>Alcance</span><span>${d.roleCount} papéis · ${d.accountCount} contas · ${d.accessCount} concessões</span></div><div class="table-wrap"><table class="table min-720"><thead><tr><th>Papel</th><th>Capacidade efetiva</th><th class="right">Contas</th><th>Privilegiado</th><th>Criticidade</th><th></th></tr></thead><tbody>${d.roles.map((role, index) => `<tr><td><div class="semibold">${escapeHtml(role.roleLabel)}</div><div class="t-sub mono">${escapeHtml(role.role)}</div></td><td>${escapeHtml(role.capability)}</td><td class="right num">${role.accounts.length}</td><td>${role.privileged ? 'Sim' : 'Não'}</td><td>${sevTag(role.severity)}</td><td class="right"><button type="button" class="btn btn-secondary btn-sm" data-project-role="${index}">Abrir contas</button></td></tr>`).join('') || emptyRow(6, 'Nenhum papel encontrado.')}</tbody></table></div>`);
    renderRoles();
    content.onclick = event => {
      const roleButton = event.target.closest('[data-project-role]');
      if (roleButton) {
        const role = d.roles[Number(roleButton.dataset.projectRole)];
        setHTML(content, `<div class="btn-row"><button type="button" class="btn btn-ghost" data-project-back>← ${escapeHtml(d.name)}</button><span class="muted">›</span><span class="semibold">${escapeHtml(role.roleLabel)}</span></div><div class="note">${escapeHtml(role.capability)}</div><div class="table-wrap"><table class="table min-640"><thead><tr><th>Conta</th><th>Tipo</th><th>E-mail</th><th>Privilegiada</th><th></th></tr></thead><tbody>${role.accounts.map(account => `<tr><td><div class="semibold">${escapeHtml(account.name)}</div><div class="t-sub">${escapeHtml(account.externalId)}</div></td><td>${TYPE_LABEL[account.type] || escapeHtml(account.type)}</td><td>${escapeHtml(account.email || 'Não fornecido')}</td><td>${account.privileged ? 'Sim' : 'Não'}</td><td class="right">${account.id ? `<button type="button" class="btn btn-secondary btn-sm" data-open-identity="${account.id}">Ver identidade</button>` : ''}</td></tr>`).join('')}</tbody></table></div>`);
      } else if (event.target.closest('[data-project-back]')) renderRoles();
      else if (event.target.closest('[data-open-identity]')) { modal.close(); openIdentityPage(Number(event.target.closest('[data-open-identity]').dataset.openIdentity)); }
    };
  } catch (error) { setHTML(content, `<div class="alert">${escapeHtml(error.message)}</div>`); }
}
function openIdentityPage(id) { navigate('identidades', { apply: () => { state.ids.selected = id; } }); }

/* ══ Inteligência e riscos ═══════════════════════════════════════════ */
async function loadRisks() {
  try {
    const [findings, rules, ai] = await Promise.all([api('/findings?finding_status=current&limit=20000'), api('/rules'), api('/ai-analyses?limit=30')]);
    Object.assign(state.risk, { findings, rules, ai });
    renderRisks();
  } catch (error) { toast(`Riscos indisponíveis: ${error.message}`); }
}
function renderRisks() {
  const r = state.risk; const open = r.findings.filter(f => f.status === 'open');
  const severities = ['critical', 'high', 'medium', 'low'];
  setHTML('#risk-sevs', severities.map(sev => `<button type="button" class="sev-counter${r.severity === sev ? ' active' : ''}" data-risk-sev="${sev}" aria-pressed="${r.severity === sev}"><span>${LEVEL[sev]}</span><b class="${sev === 'critical' ? 'crit' : ''}">${fmt(open.filter(f => f.severity === sev).length)}</b></button>`).join(''));
  const tabs = [{ code: 'all', name: 'Todas', findings: open.length }, ...r.rules];
  setHTML('#risk-tabs', tabs.map(t => `<button type="button" role="tab" class="tab${r.rule === t.code ? ' active' : ''}" aria-selected="${r.rule === t.code}" data-risk-rule="${t.code}"><span>${escapeHtml(t.name)}</span><b>${fmt(t.findings)}</b></button>`).join(''));
  const rule = r.rules.find(item => item.code === r.rule);
  const providers = [...new Set(state.credentials.map(c => c.provider))].join(', ') || 'nenhum provedor';
  setHTML('#risk-rule', `<div class="rule-info-main"><div class="card-title">${rule ? escapeHtml(rule.name) : 'Todas as regras'}</div><div>${rule ? escapeHtml(rule.description) : `Visão consolidada dos ${fmt(open.length)} riscos ativos em ${escapeHtml(providers)}, ordenados por severidade.`}</div></div><div class="rule-info-crit"><span class="overline">Critério</span><b>${rule ? escapeHtml(rule.criterion) : 'Severidade × exposição × privilégio'}</b>${rule ? `<span class="muted-sm">${escapeHtml(rule.framework)} · ${escapeHtml(rule.control)}</span>` : ''}</div>`);
  const rows = r.findings.filter(f => (r.rule === 'all' || f.rule === r.rule) && (!r.severity || f.severity === r.severity));
  const shown = pageOf('risk', rows, `${r.rule}|${r.severity}`); const readonly = isReadonly();
  setHTML('#risk-rows', shown.map(f => `<tr class="${['accepted', 'dismissed'].includes(f.status) ? 'faded' : ''}"><td>${sevTag(f.severity)}</td><td><div class="semibold break" title="${escapeHtml(`${f.why} Recomendação: ${f.recommendation}`)}">${escapeHtml(f.title)}</div><div class="t-sub break">F-${f.id} · ${escapeHtml(f.description)}</div></td><td class="break">${escapeHtml(f.identityName || '—')}</td><td>${escapeHtml(f.provider)} · ${escapeHtml(f.resourceName || f.environment)}</td><td>${escapeHtml(f.ruleName)}</td><td class="muted nowrap">${formatDate(f.firstSeen)}</td><td><span class="${STATUS_CLASS[f.status] || 'tag tag-neutral'}">${STATUS_LABEL[f.status] || escapeHtml(f.status)}</span></td><td><div class="row-actions">${readonly ? '' : f.status === 'open' ? `<button type="button" class="btn btn-primary btn-sm" data-finding-action="remediating" data-id="${f.id}">Remediar</button><button type="button" class="btn btn-secondary btn-sm" data-finding-action="accepted" data-id="${f.id}">Aceitar</button>` : `<button type="button" class="btn btn-ghost btn-sm" data-finding-action="open" data-id="${f.id}">Reabrir</button>`}</div></td></tr>`).join('') || emptyRow(8, r.findings.length ? 'Nenhum achado para este filtro.' : 'Nenhum risco identificado. Execute uma análise para avaliar as regras.'));
  const handled = r.findings.filter(f => f.status !== 'open').length;
  setHTML('#risk-foot', pagerHTML('risk', rows.length, handled ? `${fmt(handled)} em tratamento ou aceito(s)` : ''));
  const latest = []; const seen = new Set();
  for (const item of r.ai.filter(a => a.scopeType === 'platform')) { if (!seen.has(item.credentialId)) { seen.add(item.credentialId); latest.push(item); } }
  setHTML('#risk-ai', latest.length ? `<div class="cell-head"><div><div class="card-kicker">Análise local · Qwen</div><div class="card-title">Leitura dos achados por ambiente</div></div></div>${latest.slice(0, 3).map(a => { const env = state.credentials.find(c => c.id === a.credentialId); return `<div class="ai-box"><div class="cell-head"><span class="semibold">${escapeHtml(a.summary)}</span><span class="muted-sm">${escapeHtml(env?.name || 'Ambiente')} · ${escapeHtml(a.engine)} · ${formatDate(a.createdAt)}</span></div><dl class="ai-grid"><dt>Prioridade</dt><dd>${sevTag(a.priority)}</dd><dt>Por quê</dt><dd>${escapeHtml(a.why)}</dd><dt>Recomendação</dt><dd>${escapeHtml(a.recommendation)}</dd><dt>Tratativa</dt><dd>${escapeHtml(a.treatment)}</dd></dl></div>`; }).join('')}` : '');
}
async function updateFinding(id, status, justification) {
  await api(`/findings/${id}`, { method: 'PATCH', body: JSON.stringify(justification ? { status, justification } : { status }) });
  const finding = state.risk.findings.find(f => f.id === id); if (finding) finding.status = status;
  renderRisks(); loadStatus();
  toast({ remediating: 'Remediação iniciada e auditada.', accepted: 'Risco aceito com justificativa auditada.', open: 'Achado reaberto.' }[status] || 'Achado atualizado.');
}

/* ══ Acesso privilegiado ═════════════════════════════════════════════ */
async function loadPrivileged() {
  try {
    const [rows, summary] = await Promise.all([api('/privileged-access?limit=20000'), api('/privileged-access/summary')]);
    Object.assign(state.priv, { rows, summary }); renderPrivileged();
  } catch (error) { toast(`Acesso privilegiado indisponível: ${error.message}`); }
}
function renderPrivileged() {
  const p = state.priv; const s = p.summary;
  const unusedDays = state.admin.settings?.rules?.unused_days || 90;
  setHTML('#priv-kpis', [
    stat('Contas privilegiadas', fmt(s.identities), `${pct(s.identities, s.totalIdentities)}% das identidades`),
    stat('Acesso permanente', fmt(s.standing), `${pct(s.standing, s.grants)}% das concessões privilegiadas`, true),
    stat('JIT solicitado', fmt(s.jit), 'conversões registradas para execução'),
    p.rows.some(row => row.mfaEnabled !== null) ? stat('Sem MFA', fmt(s.noMfa), 'identidades privilegiadas', true) : stat('Sem MFA', '—', 'MFA não informado pelo provedor'),
    p.rows.some(row => row.lastUsedAt) ? stat(`Sem uso > ${unusedDays} dias`, fmt(s.unused), 'candidatas à revogação') : stat(`Sem uso > ${unusedDays} dias`, '—', 'sem dados de uso dos provedores'),
    stat('Break-glass', fmt(s.breakGlass), 'identificadas pelo nome'),
  ].join(''));
  const maxRole = Math.max(1, ...s.roles.map(r => r.count));
  setHTML('#priv-roles', `<div><div class="card-kicker">Papéis</div><div class="card-title">Papéis de alto impacto</div></div>${s.roles.map(r => { const active = p.role?.role === r.role && p.role?.provider === r.provider; return `<button type="button" class="role-row role-btn${active ? ' active' : ''}" data-priv-role="${escapeHtml(r.role)}" data-priv-provider="${escapeHtml(r.provider)}" aria-pressed="${active}" title="${active ? 'Remover filtro' : 'Filtrar a tabela por este papel'}"><span><span class="mono semibold">${escapeHtml(r.role)}</span> <span class="muted">· ${escapeHtml(r.provider)}</span></span><span>${fmt(r.count)}</span>${bar(r.count / maxRole * 100, '', 'bar-4 full')}</button>`; }).join('') || '<div class="empty">Nenhum papel privilegiado coletado.</div>'}<div class="stack-10 divider-top"><div class="card-title">Modelo de acesso</div><div class="split-bar">${s.grants ? `<span class="accent" data-w="${pct(s.standing, s.grants)}%"></span><span class="gray" data-w="${100 - pct(s.standing, s.grants)}%"></span>` : '<span class="gray" data-w="100%"></span>'}</div><div class="split-legend"><span><b>${fmt(s.standing)}</b> permanentes</span><span><b>${fmt(s.jit)}</b> JIT solicitado</span></div></div>`);
  const rows = p.rows.filter(row => (!p.standing || row.model === 'Permanente') && (!p.role || (row.role === p.role.role && row.provider === p.role.provider)));
  const shown = pageOf('priv', rows, `${p.standing}|${p.role?.role || ''}|${p.role?.provider || ''}`); const readonly = isReadonly();
  setHTML('#priv-filter', p.role ? `<span class="filter-chip">Papel: <b class="mono">${escapeHtml(p.role.role)}</b> · ${escapeHtml(p.role.provider)} · ${fmt(rows.length)} concessão(ões)<button type="button" class="filter-chip-x" data-priv-clear aria-label="Remover filtro de papel">×</button></span>` : '');
  const hasMfa = p.rows.some(row => row.mfaEnabled !== null); const hasUse = p.rows.some(row => row.lastUsedAt);
  setHTML('#priv-table', tableHTML('', [
    { head: 'Identidade', cell: row => `<td class="semibold break">${escapeHtml(row.identityName)}<div class="t-sub">${TYPE_LABEL[row.identityType] || escapeHtml(row.identityType || '—')}</div></td>` },
    { head: 'Papel', show: !p.role, cell: row => `<td class="mono break">${escapeHtml(row.role)}</td>` },
    { head: 'Escopo', cell: row => `<td class="break">${escapeHtml(row.resourceName)} <span class="muted">· ${escapeHtml(row.provider)}</span></td>` },
    { head: 'Modelo', cell: row => `<td><span class="tag ${row.model === 'Permanente' ? 'tag-accent' : 'tag-neutral'}">${escapeHtml(row.model)}</span></td>` },
    { head: 'MFA', show: hasMfa, cell: row => `<td class="${row.mfaEnabled === false ? 'mfa-no' : row.mfaEnabled ? 'mfa-yes' : 'muted'}">${row.mfaEnabled === false ? 'Não' : row.mfaEnabled ? 'Sim' : '—'}</td>` },
    { head: 'Último uso', show: hasUse, cell: row => `<td class="muted nowrap">${row.lastUsedAt ? ago(row.lastUsedAt) : '—'}</td>` },
    { head: 'Risco', right: true, cell: row => `<td class="right strong num" title="Base pela criticidade do papel, +10 sem MFA, +5 sem uso">${row.riskScore}</td>` },
    { head: '', cell: row => `<td class="right"><div class="row-actions vertical">${!readonly && row.model === 'Permanente' ? `<button type="button" class="btn btn-secondary btn-sm" data-jit="${row.id}">Converter para JIT</button>` : ''}<button type="button" class="btn btn-ghost btn-sm" data-dossier="${row.id}">Ver contexto</button></div></td>` },
  ], shown, null, p.rows.length ? (p.role ? 'Nenhuma conta com este papel para os filtros atuais.' : 'Nenhuma conta com acesso permanente.') : 'Nenhum acesso privilegiado coletado.'));
  setHTML('#priv-foot', pagerHTML('priv', rows.length, hiddenNote([!hasMfa && 'MFA', !hasUse && 'último uso'].filter(Boolean))));
}
async function openDossier(id) {
  const modal = $('#dossier-modal'); const content = $('#dossier-content');
  setHTML(content, '<div class="muted">Carregando contexto e análise local Qwen…</div>'); modal.showModal();
  try {
    const result = await api(`/privileged-access/${id}/analysis`, { method: 'POST' }); const d = result.dossier; const a = result.analysis;
    $('#dossier-title').textContent = `${d.identityName} · ${d.roleLabel}`;
    setHTML(content, `<div class="band top stats">${stat('Identidade', d.identityName, `${escapeHtml(TYPE_LABEL[d.identityType] || d.identityType || '—')} · ${escapeHtml(d.identityId)}`)}${stat('Ambiente', d.credential, escapeHtml(d.provider))}${stat('Projeto / recurso', d.project, `${escapeHtml(RESOURCE_LABEL[d.resourceType] || d.resourceType)} · ${escapeHtml(d.resourceId)}`)}${stat('Criticidade', LEVEL[d.severity], escapeHtml(d.capability), d.severity === 'critical')}</div>
      <div class="ai-box"><div class="card-kicker">Análise local · ${escapeHtml(result.engine)}</div><div class="card-title">${escapeHtml(a.summary || d.capability)}</div><dl class="ai-grid"><dt>Função</dt><dd class="mono">${escapeHtml(d.role)}</dd><dt>Por quê</dt><dd>${escapeHtml(a.why)}</dd><dt>Recomendação</dt><dd>${escapeHtml(a.recommendation)}</dd><dt>Tratativa</dt><dd>${escapeHtml(a.treatment)}</dd></dl></div>
      <div class="stack-6"><div class="overline">Riscos correlacionados</div>${d.relatedFindings.map(f => `<div class="risk-row">${sevTag(f.severity)}<div><div class="title">${escapeHtml(f.title)}</div><div class="muted-sm">${escapeHtml(f.description)}</div></div><span></span></div>`).join('') || '<div class="muted">Nenhum achado correlacionado.</div>'}</div>
      <div class="stack-6"><div class="overline">Caminho de acesso da identidade</div><div class="table-wrap"><table class="table min-640"><thead><tr><th>Recurso</th><th>ID</th><th>Função</th><th>Privilegiado</th></tr></thead><tbody>${d.accessPath.map(item => `<tr><td>${escapeHtml(item.resource_name)}</td><td class="mono break">${escapeHtml(item.resource_id)}</td><td class="mono">${escapeHtml(item.role_name)}</td><td>${item.privileged ? 'Sim' : 'Não'}</td></tr>`).join('')}</tbody></table></div></div>`);
  } catch (error) { setHTML(content, `<div class="alert">${escapeHtml(error.message)}</div>`); }
}

/* ══ UEBA ════════════════════════════════════════════════════════════ */
async function loadUeba() {
  try {
    state.ueba.data = await api('/ueba/overview');
    const list = state.ueba.data.anomalies;
    if (!list.some(item => item.id === state.ueba.selected)) state.ueba.selected = list[0]?.id ?? null;
    renderUeba();
  } catch (error) { toast(`UEBA indisponível: ${error.message}`); }
}
function renderUeba() {
  const u = state.ueba; const d = u.data; const k = d.kpis;
  setHTML('#ueba-kpis', [
    stat('Anomalias (24 h)', fmt(k.anomalies24h), 'eventos anômalos nos logs', true),
    stat('Alta confiança', fmt(k.highConfidence), 'desvio acima de 80', true),
    stat('Identidades afetadas', fmt(k.identities), `${fmt(k.privilegedIdentities)} privilegiada(s)`),
    stat('Eventos analisados', fmt(k.eventsEvaluated), 'logs de auditoria dos provedores'),
  ].join(''));
  const maxEvents = Math.max(1, ...d.hours.map(h => h.events));
  setHTML('#ueba-hours', d.hours.map(h => `<span class="${h.anomalies ? 'anom' : ''}" data-h="${h.events ? Math.max(2, h.events / maxEvents * 100) : 0.6}%" title="${hourMinute(h.start)} · ${fmt(h.events)} evento(s), ${fmt(h.anomalies)} anômalo(s)"></span>`).join(''));
  setHTML('#ueba-hours-x', [0, 6, 12, 18, 23].map(index => `<span>${hourMinute(d.hours[index].start).slice(0, 2)}h</span>`).join(''));
  const maxCat = Math.max(1, ...d.categories.map(c => c.count));
  setHTML('#ueba-cats', `<div><div class="card-kicker">Categorias</div><div class="card-title">Tipos de anomalia</div></div>${d.categories.map(c => `<button type="button" class="cat-row${u.category === c.name ? ' active' : ''}" data-ueba-cat="${escapeHtml(c.name)}"><span>${escapeHtml(c.name)}</span><span>${fmt(c.count)}</span>${bar(c.count / maxCat * 100, '', 'bar-4 full')}</button>`).join('') || '<div class="empty">Nenhuma anomalia classificada.</div>'}`);
  const gaps = d.coverage.filter(c => !['collected'].includes(c.status));
  $('#ueba-coverage-band').hidden = !gaps.length;
  setHTML('#ueba-coverage', gaps.length ? `<div><div class="card-kicker">Cobertura de telemetria</div><div class="card-title">Ambientes sem logs comportamentais completos</div></div>${gaps.map(c => `<div class="risk-row"><span class="tag ${c.status === 'partial' ? 'tag-outline' : 'tag-accent'}">${escapeHtml(c.provider)}</span><div><div class="title">${escapeHtml(c.environment)}</div><div class="muted-sm">${escapeHtml(c.message)}</div></div><span class="muted-sm">${c.finishedAt ? formatDate(c.finishedAt) : 'Nunca'}</span></div>`).join('')}` : '');
  const list = d.anomalies.filter(item => !u.category || item.category === u.category);
  setHTML('#ueba-list', `<div class="cell-head"><div class="card-title">${u.category ? `Anomalias · ${escapeHtml(u.category)}` : 'Anomalias recentes'}</div>${u.category ? '<button type="button" class="btn btn-ghost" data-ueba-clear>Limpar filtro</button>' : ''}</div>${list.map(a => `<button type="button" class="anom-row${a.id === u.selected ? ' selected' : ''}" data-ueba-anomaly="${a.id}"><b>${hourMinute(a.occurredAt)}</b><span><span class="anom-title">${escapeHtml(a.title)}</span><span class="anom-meta">${escapeHtml(a.who)} · ${escapeHtml(a.provider)} · ${escapeHtml(a.category)}${a.status === 'incident' ? ' · incidente aberto' : ''}</span></span><span class="anom-dev"><small>Desvio ${a.deviation}</small>${bar(a.deviation, a.deviation >= 80 ? 'var(--color-accent-700)' : 'var(--color-accent-400)')}</span></button>`).join('') || `<div class="empty">${d.coverage.length ? 'Nenhuma anomalia comportamental identificada nos logs coletados.' : 'Conecte uma credencial e execute a análise para iniciar o UEBA.'}</div>`}`);
  const selected = d.anomalies.find(item => item.id === u.selected);
  const aside = $('#ueba-aside'); aside.hidden = !selected;
  if (selected) {
    const readonly = isReadonly();
    setHTML(aside, `<div><div class="card-kicker">${escapeHtml(selected.category)} · ${hourMinute(selected.occurredAt)}</div><div class="aside-title sm">${escapeHtml(selected.title)}</div><div class="muted-sm">${escapeHtml(selected.who)} · ${escapeHtml(selected.provider)}</div></div>
      <div class="exp-obs"><div><span class="lbl">Esperado</span><span class="val">${escapeHtml(selected.expected)}</span></div><div><span class="lbl red">Observado</span><span class="val obs">${escapeHtml(selected.observed)}</span></div></div>
      <div class="dev-big"><b>${selected.deviation}</b><span>pontuação de desvio · ${escapeHtml(selected.confidence)}</span></div>
      <div class="semibold">Status: ${selected.status === 'incident' ? 'Incidente aberto' : 'Em análise'}</div>
      ${readonly ? '' : `<div class="stack-6 push-bottom"><button type="button" class="btn btn-primary btn-block" data-ueba-incident="${selected.id}"${selected.status === 'incident' ? ' disabled' : ''}>Abrir incidente</button><button type="button" class="btn btn-secondary btn-block" data-ueba-expected="${selected.id}">Marcar como comportamento esperado</button></div>`}`);
  }
}

/* ══ Credenciais ═════════════════════════════════════════════════════ */
const credentialUi = { requirements: [], scanning: new Set(), mode: 'add', editing: null, provider: 'GCP', validated: null, selected: new Set(), validating: false, saving: false, error: '' };
function credentialRequirement(provider) { return credentialUi.requirements.find(r => r.provider === provider); }
function credentialStatus(c) {
  if (credentialUi.scanning.has(c.id)) return { label: 'Em análise', tag: 'tag-outline', attention: false };
  if (c.status === 'Erro') return { label: 'Falha na última análise', tag: 'tag-accent', attention: true };
  const days = daysUntil(c.expiresAt);
  if (days !== null && days <= 0) return { label: 'Credencial expirada', tag: 'tag-accent', attention: true };
  if (days !== null && days <= EXPIRY_WARNING_DAYS) return { label: `Expira em ${days} dia${days === 1 ? '' : 's'}`, tag: 'tag-accent', attention: true };
  if (c.status === 'Conectado') return { label: 'Ativa', tag: 'tag-neutral', attention: false };
  return { label: 'Aguardando análise', tag: 'tag-outline', attention: false };
}
function collectionNote(c) {
  const notes = [];
  if (c.usageStatus && c.usageStatus !== 'collected') notes.push(`<b>Uso de permissões ${c.usageStatus === 'partial' ? 'parcial' : 'não coletado'}.</b> ${escapeHtml(c.collectionHint)}`);
  if (c.provider === 'GCP' && ['permission_denied', 'partial', 'unavailable'].includes(c.telemetryStatus)) notes.push(`<b>Logs de auditoria ${c.telemetryStatus === 'partial' ? 'parciais' : 'não coletados'}.</b> Conceda roles/logging.viewer nos projetos analisados.`);
  return notes.length ? `<div class="cred-note">${notes.join('<br>')}</div>` : '';
}
function credentialRow(c) {
  const status = credentialStatus(c); const scanning = credentialUi.scanning.has(c.id); const lock = scanning ? ' disabled' : '';
  const shown = c.scopes.slice(0, MAX_SCOPE_TAGS); const remaining = c.scopes.length - shown.length;
  const scopes = shown.map(s => `<span class="tag tag-neutral" title="${escapeHtml(s.name)}">${escapeHtml(s.label)}</span>`).join('') + (remaining > 0 ? `<span class="tag tag-neutral">+${remaining}</span>` : '');
  const scopeText = c.scopes.length ? `${c.scopes.length} ${(SCOPE_KIND[c.provider] || 'escopo').toLowerCase()}(s)` : 'escopos descobertos na primeira análise';
  const actions = isReadonly() ? '<span class="muted-sm">Somente leitura</span>' : `<button type="button" class="btn btn-secondary" data-credential-action="scan" data-id="${c.id}"${lock}>${scanning ? 'Analisando…' : c.lastSyncedAt ? 'Reanalisar' : 'Analisar'}</button><button type="button" class="btn btn-secondary" data-credential-action="edit" data-id="${c.id}"${lock}>Editar</button><button type="button" class="btn btn-ghost" data-credential-action="remove" data-id="${c.id}"${lock}>Remover</button>`;
  return `<article class="cred"><div class="cred-prov">${escapeHtml(c.provider)}</div><div class="cred-body"><div class="cred-title"><span class="cred-name">${escapeHtml(c.name)}</span><span class="tag ${status.tag}">${escapeHtml(status.label)}</span></div><div class="cred-ident" title="${escapeHtml(c.principal)}">${escapeHtml(c.kind)}${c.principal ? ` · ${escapeHtml(c.principal)}` : ''}</div>${scopes ? `<div class="cred-scopes">${scopes}</div>` : ''}${c.status === 'Erro' && c.lastError ? `<div class="cred-error">${escapeHtml(c.lastError)}</div>` : ''}${collectionNote(c)}<div class="muted-sm">Última análise: ${formatDate(c.lastSyncedAt)} · ${escapeHtml(scopeText)}</div></div><div class="cred-actions">${actions}</div></article>`;
}
function renderCredentials() {
  const creds = state.credentials; const providers = ['GCP', 'AWS', 'Azure'].filter(p => creds.some(c => c.provider === p));
  setHTML('#credential-stats', [
    stat('Credenciais', fmt(creds.length), 'cadastradas'),
    stat('Escopos analisados', fmt(creds.reduce((total, c) => total + c.scopes.length, 0)), 'projetos, contas e assinaturas'),
    stat('Provedores', fmt(providers.length), providers.length ? providers.join(' · ') : 'GCP · AWS · Azure'),
    stat('Precisam de atenção', fmt(creds.filter(c => credentialStatus(c).attention).length), 'expirando ou com falha'),
  ].join(''));
  $('#credential-empty').hidden = creds.length > 0;
  setHTML('#credential-list', creds.map(credentialRow).join(''));
}
function renderCredentialRequirements() {
  const reqs = credentialUi.requirements;
  setHTML('#credential-requirements', reqs.length ? reqs.map(r => `<div class="req"><div class="req-title">${escapeHtml(r.provider)} <span>· ${escapeHtml(r.kind)}</span></div>${r.roles.map(role => `<div class="req-perm">${escapeHtml(role)}</div>`).join('')}</div>`).join('') : '<div class="req"><div class="muted-sm">Requisitos indisponíveis: a API não respondeu.</div></div>');
}
async function loadCredentials() {
  try { state.credentials = await api('/credentials'); if (state.page === 'credenciais') renderCredentials(); } catch (error) { toast(`API indisponível: ${error.message}`); }
}
async function loadCredentialRequirements() {
  try { credentialUi.requirements = (await api('/credentials/requirements')).providers; } catch { credentialUi.requirements = []; }
  renderCredentialRequirements();
}
const credentialJson = () => $('#credential-json').value.trim();
const credentialProviderChanged = () => credentialUi.mode === 'edit' && credentialUi.provider !== credentialUi.editing.provider;
function openCredentialDialog(credential = null) {
  Object.assign(credentialUi, { mode: credential ? 'edit' : 'add', editing: credential, provider: credential?.provider || 'GCP', validated: null, selected: new Set(), validating: false, saving: false, error: '' });
  $('#credential-modal-title').textContent = credential ? 'Editar credencial' : 'Nova credencial';
  $('#credential-name').value = credential?.name || ''; $('#credential-json').value = '';
  syncCredentialDialog(); $('#credential-modal').showModal(); $('#credential-name').focus();
}
function syncCredentialDialog() {
  const ui = credentialUi; const req = credentialRequirement(ui.provider); const isEdit = ui.mode === 'edit';
  $$('input[name="credential-provider"]').forEach(radio => { radio.checked = radio.value === ui.provider; });
  $('#credential-json').placeholder = req ? JSON.stringify(Object.fromEntries(req.required[0].map(key => [key, '…'])), null, 2) : '';
  const required = req ? `Campos obrigatórios: ${req.required.map(set => set.join(', ')).join(' ou ')}.` : 'O JSON será validado conforme o provedor selecionado.';
  $('#credential-json-hint').textContent = isEdit && !credentialProviderChanged() ? 'Deixe em branco para manter a credencial atual. Uma nova credencial substitui a anterior.' : `${isEdit ? `Ao trocar para ${ui.provider}, informe uma nova credencial. ` : ''}${required}`;
  const error = $('#credential-error'); error.hidden = !ui.error; error.textContent = ui.error;
  renderCredentialValidation(); syncCredentialActions();
}
function syncCredentialActions() {
  const ui = credentialUi; const isEdit = ui.mode === 'edit'; const json = credentialJson();
  const validate = $('#credential-validate');
  validate.hidden = Boolean(ui.validated) || (isEdit && !json); validate.disabled = ui.validating || ui.saving;
  validate.textContent = ui.validating ? 'Analisando acesso…' : 'Validar credencial';
  const needsValidation = !isEdit || Boolean(json) || credentialProviderChanged();
  const save = $('#credential-save');
  save.disabled = ui.saving || ui.validating || (needsValidation && !ui.validated) || Boolean(ui.validated && !ui.selected.size);
  save.textContent = ui.saving ? 'Salvando…' : isEdit ? 'Salvar alterações' : 'Salvar integração';
}
function renderCredentialValidation() {
  const ui = credentialUi; const box = $('#credential-validated'); const v = ui.validated;
  box.hidden = !v;
  if (!v) { box.innerHTML = ''; return; }
  const kind = SCOPE_KIND[ui.provider] || 'Escopo';
  const scopes = v.scopes.map(s => `<label class="check-row"><input type="checkbox" class="checkbox" data-scope-id="${escapeHtml(s.id)}"${ui.selected.has(s.id) ? ' checked' : ''}><span class="name">${escapeHtml(s.label)}</span><span class="muted-sm">${kind}</span></label>`).join('');
  const checks = v.checks.map(k => `<div class="perm${k.granted ? '' : ' missing'}">${k.granted ? ICON.check : ICON.cross}<span class="mono break">${escapeHtml(k.permission)}</span>${k.granted ? '' : '<span class="muted-sm">opcional · não concedida</span>'}</div>`).join('');
  const toggle = v.scopes.length > 1 ? `<button type="button" class="btn btn-ghost btn-xs" data-scope-all>${ui.selected.size === v.scopes.length ? 'Desmarcar todos' : 'Marcar todos'}</button>` : '';
  setHTML(box, `<div class="validated-head"><span class="strong">Acesso validado</span><span class="mono muted-sm break">${escapeHtml(v.identity)}</span></div>${v.expiresAt ? `<div class="muted-sm">Validade da credencial: até ${formatDate(v.expiresAt)}</div>` : ''}<div class="overline-row"><span class="overline-12">Escopos detectados · selecione o que analisar</span>${toggle}</div><div class="scope-list">${scopes}</div><div class="overline-12">Permissões verificadas</div>${checks}`);
}
async function validateCredentialForm() {
  const ui = credentialUi; const raw = credentialJson(); const provider = ui.provider; let parsed;
  try { parsed = JSON.parse(raw); } catch { Object.assign(ui, { error: 'JSON inválido: verifique aspas, vírgulas e chaves.', validated: null }); return syncCredentialDialog(); }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') { Object.assign(ui, { error: 'A credencial precisa ser um objeto JSON.', validated: null }); return syncCredentialDialog(); }
  Object.assign(ui, { error: '', validating: true }); syncCredentialDialog();
  const current = () => provider === ui.provider && raw === credentialJson();
  try {
    const result = await api('/credentials/validate', { method: 'POST', body: JSON.stringify({ provider, credential: parsed }) });
    if (!current()) return;
    const saved = new Set(ui.editing?.provider === provider ? ui.editing.scopes.map(s => s.id) : []);
    const kept = result.scopes.filter(s => saved.has(s.id));
    ui.validated = result; ui.selected = new Set((kept.length ? kept : result.scopes).map(s => s.id));
  } catch (error) { if (current()) ui.error = error.message; } finally { ui.validating = false; syncCredentialDialog(); }
}
function suggestedCredentialName(scopes) {
  const slug = `${credentialUi.provider}-${scopes?.[0]?.id || 'integracao'}`.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
  return slug.length >= 2 ? slug : 'nova-integracao';
}
async function saveCredentialForm() {
  const ui = credentialUi; const isEdit = ui.mode === 'edit'; const v = ui.validated; const modal = $('#credential-modal');
  const scopes = v ? v.scopes.filter(s => ui.selected.has(s.id)) : null;
  const body = { name: $('#credential-name').value.trim() || (isEdit ? ui.editing.name : suggestedCredentialName(scopes)), provider: ui.provider };
  if (v) { body.credential = JSON.parse(credentialJson()); body.scopes = scopes; }
  Object.assign(ui, { saving: true, error: '' }); syncCredentialDialog();
  try {
    const saved = await api(isEdit ? `/credentials/${ui.editing.id}` : '/credentials', { method: isEdit ? 'PUT' : 'POST', body: JSON.stringify(body) });
    modal.close();
    await loadCredentials(); loadStatus();
    if (!v) { toast('Credencial atualizada.'); return; }
    toast(isEdit ? `Credencial atualizada. Análise iniciada em ${scopes.length} escopo(s).` : `Credencial "${saved.name}" adicionada. Análise iniciada em ${scopes.length} escopo(s).`, 4000);
    scanCredential(saved.id, { announce: false });
  } catch (error) { ui.error = error.message; } finally { ui.saving = false; if (modal.open) syncCredentialDialog(); }
}
function openRemoveCredential(id) {
  const c = state.credentials.find(item => item.id === id); if (!c) return;
  confirmDialog({ title: 'Remover credencial?', ok: 'Remover credencial', text: `A integração "${c.name}" (${c.provider}) será removida e ${c.scopes.length} escopo(s) deixarão de ser analisados. Achados históricos ficam preservados na Auditoria.`,
    onConfirm: async () => { await api(`/credentials/${c.id}`, { method: 'DELETE' }); await loadCredentials(); loadStatus(); toast(`Credencial "${c.name}" removida.`); } });
}
async function scanCredential(id, { announce = true } = {}) {
  if (credentialUi.scanning.has(id)) return;
  credentialUi.scanning.add(id); if (state.page === 'credenciais') renderCredentials();
  if (announce) toast('Análise em andamento. Aguarde a coleta do provedor.', 300000);
  try {
    const result = await api(`/credentials/${id}/scan`, { method: 'POST' });
    credentialUi.scanning.delete(id); await loadCredentials(); refreshCurrent();
    toast(`Análise concluída: ${result.findings} riscos encontrados.`);
  } catch (error) { credentialUi.scanning.delete(id); await loadCredentials(); loadStatus(); toast(error.message, 5000); } finally { credentialUi.scanning.delete(id); if (state.page === 'credenciais') renderCredentials(); }
}

/* ══ Auditoria ═══════════════════════════════════════════════════════ */
async function loadAudit() {
  try {
    state.audit.data = await api('/audit/trail?limit=2000');
    const rows = filteredAudit(); if (!rows.some(e => e.key === state.audit.selected)) state.audit.selected = rows[0]?.key ?? null;
    renderAudit();
  } catch (error) { toast(`Auditoria indisponível: ${error.message}`); }
}
function filteredAudit() {
  const a = state.audit; const query = a.q.trim().toLowerCase();
  return (a.data?.events || []).filter(e => (!a.source || e.source === a.source) && (a.result === 'all' || (a.result === 'ok' ? e.result === 'Sucesso' : e.result !== 'Sucesso'))
    && (!query || `${e.actor} ${e.action} ${e.target} ${e.title} ${e.text}`.toLowerCase().includes(query)));
}
function renderAudit() {
  const a = state.audit; const rows = filteredAudit(); const shown = pageOf('audit', rows, `${a.source}|${a.result}|${a.q}`);
  setHTML('#audit-sources', a.data.sources.map(s => `<button type="button" class="stat clickable${a.source === s.name ? ' active' : ''}" data-audit-source="${escapeHtml(s.name)}"><span class="stat-label">${escapeHtml(s.name)}</span><span class="stat-value">${fmt(s.count)}</span><span class="stat-sub">${s.collected ? 'eventos em 24 h' : 'não coletado pelos conectores'}</span></button>`).join(''));
  $('#audit-count').textContent = `${fmt(rows.length)} eventos${a.source ? ` · ${a.source}` : ''}`;
  setHTML('#audit-rows', shown.map(e => `<tr class="clickable${e.key === a.selected ? ' selected' : ''}" data-audit-key="${escapeHtml(e.key)}"><td class="num nowrap">${formatDate(e.createdAt)}</td><td class="semibold break">${escapeHtml(e.actor)}</td><td class="mono break">${escapeHtml(e.action)}</td><td class="break">${escapeHtml(e.target)}</td><td>${escapeHtml(e.source)}</td><td><span class="tag ${e.result === 'Sucesso' ? 'tag-neutral' : 'tag-accent'}">${escapeHtml(e.result)}</span></td></tr>`).join('') || emptyRow(6, 'Nenhum evento para este filtro.'));
  setHTML('#audit-foot', pagerHTML('audit', rows.length));
  const selected = (a.data?.events || []).find(e => e.key === a.selected);
  const aside = $('#audit-aside'); aside.hidden = !selected;
  if (selected) {
    const record = { timestamp: selected.createdAt, actor: selected.actor, action: selected.action, target: selected.target, source: selected.source, result: selected.result, description: selected.text, details: selected.details };
    setHTML(aside, `<div><div class="card-kicker">${escapeHtml(selected.source)}</div><div class="aside-action">${escapeHtml(selected.action)}</div><div class="muted-sm">${formatDate(selected.createdAt)}</div></div><pre class="json">${escapeHtml(JSON.stringify(record, null, 2))}</pre><div class="muted-sm break">Hash do registro: sha256:${escapeHtml(selected.hash || '—')}${selected.key.startsWith('A-') ? ' · encadeado ao registro anterior' : ' · calculado sobre o evento do provedor'}</div>`);
  }
}

/* ══ Compliance ══════════════════════════════════════════════════════ */
async function loadCompliance() {
  try {
    const [report, campaigns] = await Promise.all([api('/compliance/frameworks'), api('/reviews')]);
    Object.assign(state.comp, { frameworks: report.frameworks, campaigns }); renderCompliance();
  } catch (error) { toast(`Compliance indisponível: ${error.message}`); }
}
function renderCompliance() {
  const c = state.comp; const current = c.frameworks.find(f => f.key === c.fw) || c.frameworks[0];
  setHTML('#comp-fws', c.frameworks.map(f => `<button type="button" class="fw-card${f.key === current.key ? ' active' : ''}" data-fw="${f.key}"><span class="fw-name">${escapeHtml(f.name)}</span><span class="fw-pct">${f.assessed ? `${f.percent}%` : '—'}</span>${bar(f.percent, f.percent < 50 ? 'var(--color-accent)' : 'var(--color-text)', 'bar-8')}<span class="muted-sm">${f.met} de ${f.total} controles atendidos${f.total - f.assessed ? ` · ${f.total - f.assessed} não avaliado(s)` : ''}</span></button>`).join(''));
  const statusClass = s => s === 'Atendido' ? 'tag tag-neutral' : s === 'Parcial' ? 'tag tag-outline' : s === 'Não atendido' ? 'tag tag-accent' : 'tag tag-neutral muted';
  setHTML('#comp-controls', `<div><div class="card-kicker">Controles</div><div class="card-title">${escapeHtml(current.name)} · controles de identidade e acesso</div></div><div class="table-wrap"><table class="table min-640"><thead><tr><th>Controle</th><th>Descrição</th><th>Regra vinculada</th><th>Status</th><th>Evidência</th></tr></thead><tbody>${current.controls.map(ctrl => `<tr><td class="mono semibold nowrap">${escapeHtml(ctrl.id)}</td><td>${escapeHtml(ctrl.description)}</td><td>${escapeHtml(ctrl.rule)}</td><td><span class="${statusClass(ctrl.status)}">${escapeHtml(ctrl.status)}</span></td><td class="muted">${escapeHtml(ctrl.evidence)}</td></tr>`).join('')}</tbody></table></div>`);
  setHTML('#comp-camps', c.campaigns.map(camp => { const due = camp.completedAt ? `concluída ${dayMonth(camp.completedAt)}` : camp.overdue ? `vencida ${dayMonth(camp.dueAt)}` : `vence ${dayMonth(camp.dueAt)}`; return `<button type="button" class="camp" data-campaign="${camp.id}"><span class="camp-top"><span>${escapeHtml(camp.name)}</span><span class="strong">${camp.percent}%</span></span>${bar(camp.percent, camp.percent === 100 ? 'var(--color-neutral-500)' : 'var(--color-text)')}<span class="camp-meta"><span>${fmt(camp.total)} itens · revisor ${escapeHtml(camp.reviewer)}</span><span class="${camp.overdue ? 'overdue' : ''}">${due}</span></span></button>`; }).join('') || '<div class="empty">Nenhuma campanha criada. Crie uma campanha para recertificar acessos.</div>');
}
function openNewReview(scope, identity) {
  const env = $('#review-env');
  env.innerHTML = '<option value="">Todos os ambientes</option>' + state.credentials.map(c => `<option value="${c.id}">${escapeHtml(c.provider)} · ${escapeHtml(c.name)}</option>`).join('');
  $('#review-scope-identity').hidden = scope !== 'identity';
  $$('input[name="review-scope"]').forEach(radio => { radio.checked = radio.value === scope; radio.disabled = scope === 'identity' && radio.value !== 'identity'; });
  env.disabled = scope === 'identity';
  const unusedDays = state.admin.settings?.rules?.unused_days || 90;
  const names = { privileged: 'Contas privilegiadas', unused: `Acessos sem uso > ${unusedDays} dias`, all: 'Revisão de acessos', identity: `Revisão de ${identity?.name || 'identidade'}` };
  $('#review-name').value = `${names[scope]} · ${new Intl.DateTimeFormat('pt-BR', { month: 'short', year: 'numeric' }).format(new Date())}`;
  $('#review-reviewer').value = state.user?.email || ''; $('#review-due').value = 30;
  $('#review-new-error').hidden = true;
  const modal = $('#review-new-modal'); modal.dataset.identityId = identity?.id || '';
  $('#review-scopes').onchange = () => { const value = $('input[name="review-scope"]:checked').value; if (value !== 'identity') $('#review-name').value = `${names[value]} · ${new Intl.DateTimeFormat('pt-BR', { month: 'short', year: 'numeric' }).format(new Date())}`; };
  modal.showModal();
}
async function createReview() {
  const modal = $('#review-new-modal'); const error = $('#review-new-error'); const button = $('#review-create');
  const scope = $('input[name="review-scope"]:checked').value;
  const payload = { name: $('#review-name').value.trim(), scope, reviewer: $('#review-reviewer').value.trim(), dueDays: Number($('#review-due').value) || 30, credentialId: $('#review-env').value ? Number($('#review-env').value) : null, identityId: modal.dataset.identityId ? Number(modal.dataset.identityId) : null };
  button.disabled = true;
  try {
    const campaign = await api('/reviews', { method: 'POST', body: JSON.stringify(payload) });
    modal.close(); toast(`Campanha criada com ${fmt(campaign.total)} item(ns).`);
    if (state.page === 'compliance') loadCompliance(); else navigate('compliance');
    openCampaign(campaign.id);
  } catch (failure) { error.textContent = failure.message; error.hidden = false; } finally { button.disabled = false; }
}
async function openCampaign(id) {
  const modal = $('#review-modal'); if (!modal.open) modal.showModal();
  setHTML('#review-items', '<div class="muted">Carregando itens…</div>');
  try {
    const c = await api(`/reviews/${id}`);
    const scopeLabel = { privileged: 'Acessos privilegiados', unused: 'Concessões sem uso', all: 'Todas as concessões', identity: 'Identidade' }[c.scope];
    $('#review-kicker').textContent = `${c.environment} · ${scopeLabel}`; $('#review-title').textContent = c.name;
    $('#review-meta').textContent = `${fmt(c.decided)} de ${fmt(c.total)} decididos (${c.percent}%) · ${fmt(c.kept)} mantidos · ${fmt(c.revoked)} revogações solicitadas · revisor ${c.reviewer} · ${c.completedAt ? `concluída ${formatDate(c.completedAt)}` : `vence ${formatDate(c.dueAt)}`}`;
    const readonly = isReadonly();
    setHTML('#review-items', c.items.map(item => `<div class="review-item"><div class="break"><div class="semibold">${escapeHtml(item.identity)}${item.privileged ? ' <span class="tag tag-accent">Privilegiado</span>' : ''}</div><div class="muted-sm"><span class="mono">${escapeHtml(item.role)}</span> em ${escapeHtml(item.resource)}</div></div><div class="row-actions">${item.decision ? `<span class="tag ${item.decision === 'keep' ? 'tag-neutral' : 'tag-accent'}">${item.decision === 'keep' ? 'Mantido' : 'Revogação solicitada'}</span><span class="muted-sm">${escapeHtml(item.decidedBy || '')}</span>` : readonly ? '<span class="tag tag-outline">Pendente</span>' : `<button type="button" class="btn btn-secondary btn-sm" data-review-item="${item.id}" data-decision="keep" data-campaign-id="${c.id}">Manter</button><button type="button" class="btn btn-primary btn-sm" data-review-item="${item.id}" data-decision="revoke" data-campaign-id="${c.id}">Revogar</button>`}</div></div>`).join('') || '<div class="empty">Campanha sem itens.</div>');
  } catch (error) { setHTML('#review-items', `<div class="alert">${escapeHtml(error.message)}</div>`); }
}

/* ══ Administração ═══════════════════════════════════════════════════ */
async function loadSettings() { try { state.admin.settings = await api('/settings'); } catch { /* optional for non-admin pages */ } }
async function loadAdmin() {
  try {
    const [settings, users] = await Promise.all([api('/settings'), api('/users')]);
    Object.assign(state.admin, { settings, users }); renderAdmin();
  } catch (error) { toast(`Administração indisponível: ${error.message}`); }
}
function renderAdmin() {
  const s = state.admin.settings;
  setHTML('#settings-params', s.parameters.map(p => `<div class="param-row"><div><div class="p-name">${escapeHtml(p.name)}</div><div class="p-desc">${escapeHtml(p.description)}</div></div><input class="input" type="number" min="${p.min}" max="${p.max}" value="${p.value}" data-param="${p.key}" aria-label="${escapeHtml(`${p.name}: ${p.description}`)}"><span class="p-unit">${escapeHtml(p.unit)}</span></div>`).join(''));
  $$('input[name="schedule"]').forEach(radio => { radio.checked = radio.value === s.schedule; });
  renderNextRun();
  $$('[data-notif]').forEach(box => { box.checked = Boolean(s.notifications[box.dataset.notif]); });
  $('#settings-webhook').value = s.webhook || '';
  renderUsers();
}
function renderNextRun() {
  const s = state.admin.settings; const schedule = $('input[name="schedule"]:checked')?.value || s.schedule;
  $('#settings-next').textContent = schedule === 'manual' ? 'Análise somente sob demanda (botão Analisar em Credenciais).'
    : schedule !== s.schedule ? 'Salve para aplicar o novo agendamento.'
    : s.nextRunAt ? `Próxima análise: ${new Intl.DateTimeFormat('pt-BR', { dateStyle: 'short' }).format(new Date(s.nextRunAt))} às ${hourMinute(s.nextRunAt)}` : 'Cadastre uma credencial para agendar a análise.';
}
function renderUsers() {
  setHTML('#users-rows', state.admin.users.map(u => `<tr><td class="semibold">${escapeHtml(u.name)}</td><td>${escapeHtml(u.email)}</td><td><span class="tag tag-neutral">${ROLE_LABEL[u.role] || escapeHtml(u.role)}</span></td><td>${u.active ? 'Ativo' : '<span class="accent-text semibold">Inativo</span>'}</td><td class="muted">${u.lastLoginAt ? ago(u.lastLoginAt) : 'Nunca acessou'}</td><td class="right"><div class="row-actions">${u.id === state.user.id ? '<span class="muted-sm">Sessão atual</span>' : `<button type="button" class="btn btn-ghost btn-sm" data-user-toggle="${u.id}">${u.active ? 'Desativar' : 'Ativar'}</button><button type="button" class="btn btn-ghost btn-sm" data-user-remove="${u.id}">Remover</button>`}</div></td></tr>`).join('') || emptyRow(6, 'Nenhum usuário.'));
}
async function saveSettings() {
  const rules = Object.fromEntries($$('[data-param]').map(input => [input.dataset.param, Number(input.value)]));
  const payload = { rules, schedule: $('input[name="schedule"]:checked').value, notifications: Object.fromEntries($$('[data-notif]').map(box => [box.dataset.notif, box.checked])), webhook: $('#settings-webhook').value.trim() };
  const button = $('#settings-save'); button.disabled = true;
  try { state.admin.settings = await api('/settings', { method: 'PUT', body: JSON.stringify(payload) }); renderAdmin(); toast('Configurações salvas. Aplicadas na próxima análise.'); }
  catch (error) { toast(error.message, 5000); } finally { button.disabled = false; }
}

/* ══ events ══════════════════════════════════════════════════════════ */
function applyRoleVisibility() { document.body.classList.toggle('readonly', isReadonly()); }
const PAGERS = { ids: () => renderIdentities(), acc: () => renderAccesses(), risk: () => renderRisks(), priv: () => renderPrivileged(), audit: () => renderAudit() };
document.addEventListener('click', event => {
  const target = event.target;
  const pager = target.closest('[data-pager]');
  if (pager) {
    const key = pager.dataset.pager; pages[key].index += Number(pager.dataset.step); PAGERS[key]();
    const table = pager.closest('.cell, section')?.querySelector('.table'); if (table && table.getBoundingClientRect().top < 0) table.scrollIntoView({ block: 'start' });
    return;
  }
  const closer = target.closest('[data-close]'); if (closer) { closer.closest('dialog')?.close(); return; }
  const nav = target.closest('[data-nav]'); if (nav) { navigate(nav.dataset.nav); return; }
  const review = target.closest('[data-new-review]'); if (review) { openNewReview(review.dataset.newReview, review.dataset.identityId ? { id: review.dataset.identityId, name: review.dataset.identityName } : null); return; }
  const goRule = target.closest('[data-go-rule]'); if (goRule) { navigate('riscos', { apply: () => { state.risk.rule = goRule.dataset.goRule; state.risk.severity = null; } }); return; }
  const goRisk = target.closest('[data-go-risk]'); if (goRisk) { navigate('riscos', { apply: () => { state.risk.rule = 'all'; state.risk.severity = goRisk.dataset.goRisk; } }); return; }
  const project = target.closest('[data-open-project]'); if (project) { openProject(project.dataset.openProject, project.dataset.resource); return; }
  const identity = target.closest('[data-open-identity]'); if (identity && !target.closest('#project-content')) { openIdentityPage(Number(identity.dataset.openIdentity)); return; }
});
$('#menu-btn').addEventListener('click', () => { $('#sidebar').classList.add('open'); $('#scrim').classList.add('open'); });
$('#scrim').addEventListener('click', closeDrawer);
$('#alerts-btn').addEventListener('click', () => navigate(state.status?.criticalOpen || !state.status?.attention ? 'riscos' : 'credenciais', { apply: () => { state.risk.rule = 'all'; state.risk.severity = state.status?.criticalOpen ? 'critical' : null; } }));
$('#global-search').addEventListener('keydown', event => { if (event.key === 'Enter' && event.target.value.trim()) { const q = event.target.value.trim(); navigate('identidades', { apply: () => { state.ids.q = q; $('#id-search').value = q; state.ids.selected = null; } }); } });
$('#logout').addEventListener('click', showLogin);

// Visão geral
$('#dash-env').addEventListener('change', event => { state.dash.credentialId = event.target.value === 'all' ? null : Number(event.target.value); state.dash.provider = null; loadDashboard(); });
$$('input[name="dash-period"]').forEach(radio => radio.addEventListener('change', () => { if (radio.checked) { state.dash.period = Number(radio.value); loadDashboard(); } }));
$('#dash-body').addEventListener('click', event => { const card = event.target.closest('[data-provider]'); if (card) { state.dash.provider = state.dash.provider === card.dataset.provider ? null : card.dataset.provider; state.dash.credentialId = null; loadDashboard(); } });

// Identidades
$$('input[name="id-type"]').forEach(radio => radio.addEventListener('change', () => { if (radio.checked) { state.ids.type = radio.value; renderIdentities(); } }));
$('#id-provider').addEventListener('change', event => { state.ids.provider = event.target.value; renderIdentities(); });
let idSearchTimer;
$('#id-search').addEventListener('input', event => { clearTimeout(idSearchTimer); idSearchTimer = setTimeout(() => { state.ids.q = event.target.value; renderIdentities(); }, 180); });
$('#id-table').addEventListener('click', event => { const row = event.target.closest('[data-identity]'); if (row) selectIdentity(Number(row.dataset.identity)); });
$('#id-aside').addEventListener('click', event => {
  if (event.target.closest('[data-close-aside]')) { state.ids.selected = null; $('#id-aside').hidden = true; renderIdentities(); return; }
  const accesses = event.target.closest('[data-identity-accesses]');
  if (accesses) navigate('acessos', { apply: () => { Object.assign(state.acc, { view: 'grants', q: accesses.dataset.identityAccesses }); $('#acc-search').value = accesses.dataset.identityAccesses; $$('input[name="acc-view"]').forEach(r => { r.checked = r.value === 'grants'; }); } });
});
$('#id-export').addEventListener('click', () => downloadCsv('identidades-nexo-iga.csv', ['Nome', 'E-mail / ID', 'Tipo', 'Provedor', 'Ambiente', 'Acessos', 'Privilegiados', 'Nota de risco', 'Ciclo de vida', 'MFA', 'Último login'],
  filteredIdentities().map(i => [i.name, i.email || i.externalId, TYPE_LABEL[i.type] || i.type, i.provider, i.environment, i.accessCount, i.privilegedCount, i.riskScore, i.lifecycleStatus || '', i.mfaEnabled === null ? 'Não informado' : i.mfaEnabled ? 'Sim' : 'Não', i.lastSeenAt || ''])));

// Acessos
$$('input[name="acc-view"]').forEach(radio => radio.addEventListener('change', async () => { if (!radio.checked) return; state.acc.view = radio.value; try { await loadAccessView(); } catch (error) { toast(error.message); } renderAccesses(); }));
$$('input[name="acc-prov"]').forEach(radio => radio.addEventListener('change', () => { if (radio.checked) { state.acc.prov = radio.value; renderAccesses(); } }));
$('#acc-unused').addEventListener('change', event => { state.acc.unused = event.target.checked; renderAccesses(); });
let accSearchTimer;
$('#acc-search').addEventListener('input', event => { clearTimeout(accSearchTimer); accSearchTimer = setTimeout(() => { state.acc.q = event.target.value; renderAccesses(); }, 180); });
$('#acc-export').addEventListener('click', () => { const a = state.acc; downloadCsv('acessos-nexo-iga.csv', ['Identidade', 'ID', 'Recurso', 'Provedor', 'Ambiente', 'Papel', 'Origem', 'Privilegiado', 'Concedido', 'Último uso', 'Permissões usadas', 'Permissões do papel'],
  a.grants.filter(g => (a.prov === 'all' || g.provider === a.prov) && (!a.unused || isStale(g)) && accessMatches(`${g.identityName} ${g.identityId} ${g.resourceName} ${g.role}`)).map(g => [g.identityName, g.identityId, g.resourceName, g.provider, g.environment, g.role, g.origin, g.privileged ? 'Sim' : 'Não', g.grantedAt || '', g.lastUsedAt || 'Sem telemetria', g.usedPermissions ?? '', g.totalPermissions ?? ''])); });

// Riscos
$('#risk-sevs').addEventListener('click', event => { const button = event.target.closest('[data-risk-sev]'); if (button) { state.risk.severity = state.risk.severity === button.dataset.riskSev ? null : button.dataset.riskSev; renderRisks(); } });
$('#risk-tabs').addEventListener('click', event => { const tab = event.target.closest('[data-risk-rule]'); if (tab) { state.risk.rule = tab.dataset.riskRule; renderRisks(); } });
$('#risk-rows').addEventListener('click', async event => {
  const button = event.target.closest('[data-finding-action]'); if (!button) return;
  const id = Number(button.dataset.id); const action = button.dataset.findingAction; const finding = state.risk.findings.find(f => f.id === id);
  if (action === 'accepted') { justifyDialog({ title: 'Aceitar risco?', text: `${finding.title} · ${finding.identityName || finding.environment}`, ok: 'Aceitar risco', onConfirm: justification => updateFinding(id, 'accepted', justification) }); return; }
  button.disabled = true; try { await updateFinding(id, action); } catch (error) { toast(error.message); button.disabled = false; }
});

// Privilegiado
$('#priv-standing').addEventListener('change', event => { state.priv.standing = event.target.checked; renderPrivileged(); });
$('#priv-roles').addEventListener('click', event => {
  const button = event.target.closest('[data-priv-role]'); if (!button) return;
  const { privRole: role, privProvider: provider } = button.dataset; const current = state.priv.role;
  state.priv.role = current && current.role === role && current.provider === provider ? null : { role, provider };
  renderPrivileged();
});
$('#priv-filter').addEventListener('click', event => { if (event.target.closest('[data-priv-clear]')) { state.priv.role = null; renderPrivileged(); } });
$('#priv-table').addEventListener('click', async event => {
  const dossier = event.target.closest('[data-dossier]'); if (dossier) { openDossier(Number(dossier.dataset.dossier)); return; }
  const jit = event.target.closest('[data-jit]'); if (!jit) return;
  const row = state.priv.rows.find(item => item.id === Number(jit.dataset.jit));
  confirmDialog({ title: 'Converter para JIT?', ok: 'Solicitar conversão', text: `O acesso ${row.role} de ${row.identityName} em ${row.resourceName} será registrado para conversão em just-in-time. A plataforma só lê o ambiente: a remoção do acesso permanente deve ser executada no provedor pelo responsável.`,
    onConfirm: async () => { const updated = await api(`/privileged-access/${row.id}/jit`, { method: 'POST', body: JSON.stringify({}) }); Object.assign(row, updated); state.priv.summary = await api('/privileged-access/summary'); renderPrivileged(); toast('Conversão para JIT registrada e auditada.'); } });
});

// UEBA
$('#ueba-cats').addEventListener('click', event => { const cat = event.target.closest('[data-ueba-cat]'); if (cat) { state.ueba.category = state.ueba.category === cat.dataset.uebaCat ? null : cat.dataset.uebaCat; renderUeba(); } });
$('#ueba-list').addEventListener('click', event => {
  if (event.target.closest('[data-ueba-clear]')) { state.ueba.category = null; renderUeba(); return; }
  const row = event.target.closest('[data-ueba-anomaly]'); if (row) { state.ueba.selected = Number(row.dataset.uebaAnomaly); renderUeba(); }
});
$('#ueba-aside').addEventListener('click', async event => {
  const incident = event.target.closest('[data-ueba-incident]');
  if (incident) { incident.disabled = true; try { await api(`/findings/${incident.dataset.uebaIncident}`, { method: 'PATCH', body: JSON.stringify({ status: 'incident' }) }); toast('Incidente aberto e registrado na auditoria.'); loadUeba(); loadStatus(); } catch (error) { toast(error.message); incident.disabled = false; } return; }
  const expected = event.target.closest('[data-ueba-expected]');
  if (expected) { const id = Number(expected.dataset.uebaExpected); const item = state.ueba.data.anomalies.find(a => a.id === id);
    justifyDialog({ title: 'Marcar como comportamento esperado?', text: `${item.title} · ${item.who}`, ok: 'Confirmar', onConfirm: async justification => { await api(`/findings/${id}`, { method: 'PATCH', body: JSON.stringify({ status: 'accepted', justification }) }); state.ueba.selected = null; toast('Comportamento marcado como esperado.'); loadUeba(); loadStatus(); } }); }
});

// Credenciais
['#new-credential-top', '#new-credential-page', '#new-credential-empty'].forEach(selector => $(selector).addEventListener('click', () => openCredentialDialog()));
$('#credential-list').addEventListener('click', event => {
  const button = event.target.closest('[data-credential-action]'); if (!button) return;
  const c = state.credentials.find(item => item.id === Number(button.dataset.id)); if (!c) return;
  ({ scan: () => scanCredential(c.id), edit: () => openCredentialDialog(c), remove: () => openRemoveCredential(c.id) })[button.dataset.credentialAction]?.();
});
$('#credential-modal').addEventListener('cancel', event => { if (credentialUi.saving) event.preventDefault(); });
$$('input[name="credential-provider"]').forEach(radio => radio.addEventListener('change', () => { if (radio.checked) { Object.assign(credentialUi, { provider: radio.value, validated: null, error: '' }); syncCredentialDialog(); } }));
$('#credential-json').addEventListener('input', () => { if (credentialUi.validated || credentialUi.error) { Object.assign(credentialUi, { validated: null, error: '' }); syncCredentialDialog(); } else syncCredentialActions(); });
$('#credential-sample').addEventListener('click', () => { const req = credentialRequirement(credentialUi.provider); if (!req) return; const field = $('#credential-json'); field.value = JSON.stringify(req.sample, null, 2); Object.assign(credentialUi, { validated: null, error: '' }); syncCredentialDialog(); field.focus(); });
$('#credential-validate').addEventListener('click', validateCredentialForm);
$('#credential-save').addEventListener('click', saveCredentialForm);
$('#credential-validated').addEventListener('change', event => {
  const box = event.target.closest('[data-scope-id]'); if (!box) return;
  if (box.checked) credentialUi.selected.add(box.dataset.scopeId); else credentialUi.selected.delete(box.dataset.scopeId);
  const toggle = $('[data-scope-all]'); if (toggle) toggle.textContent = credentialUi.selected.size === credentialUi.validated.scopes.length ? 'Desmarcar todos' : 'Marcar todos';
  syncCredentialActions();
});
$('#credential-validated').addEventListener('click', event => {
  if (!event.target.closest('[data-scope-all]')) return;
  const scopes = credentialUi.validated.scopes;
  credentialUi.selected = credentialUi.selected.size === scopes.length ? new Set() : new Set(scopes.map(s => s.id));
  renderCredentialValidation(); syncCredentialActions();
});

// Auditoria
$('#audit-sources').addEventListener('click', event => { const source = event.target.closest('[data-audit-source]'); if (source) { state.audit.source = state.audit.source === source.dataset.auditSource ? null : source.dataset.auditSource; renderAudit(); } });
$$('input[name="audit-result"]').forEach(radio => radio.addEventListener('change', () => { if (radio.checked) { state.audit.result = radio.value; renderAudit(); } }));
$('#audit-search').addEventListener('input', event => { state.audit.q = event.target.value; renderAudit(); });
$('#audit-rows').addEventListener('click', event => { const row = event.target.closest('[data-audit-key]'); if (row) { state.audit.selected = row.dataset.auditKey; renderAudit(); } });
$('#audit-export').addEventListener('click', () => downloadCsv('auditoria-nexo-iga.csv', ['Data/hora', 'Ator', 'Ação', 'Alvo', 'Origem', 'Resultado', 'Descrição', 'Detalhes', 'Hash SHA-256'],
  filteredAudit().map(e => [e.createdAt, e.actor, e.action, e.target, e.source, e.result, e.text, JSON.stringify(e.details), e.hash || ''])));

// Compliance
$('#comp-fws').addEventListener('click', event => { const card = event.target.closest('[data-fw]'); if (card) { state.comp.fw = card.dataset.fw; renderCompliance(); } });
$('#comp-camps').addEventListener('click', event => { const camp = event.target.closest('[data-campaign]'); if (camp) openCampaign(Number(camp.dataset.campaign)); });
$('#comp-report').addEventListener('click', () => {
  const rows = state.comp.frameworks.flatMap(f => f.controls.map(c => [f.name, `${f.percent}%`, c.id, c.description, c.rule, c.status, c.evidence]));
  const camps = state.comp.campaigns.map(c => ['Access Review', `${c.percent}%`, c.name, `${c.total} itens · ${c.kept} mantidos · ${c.revoked} revogações`, c.reviewer, c.completedAt ? 'Concluída' : c.overdue ? 'Vencida' : 'Em andamento', c.dueAt]);
  downloadCsv(`relatorio-compliance-${new Date().toISOString().slice(0, 10)}.csv`, ['Framework', 'Atendimento', 'Controle', 'Descrição', 'Regra vinculada', 'Status', 'Evidência'], [...rows, ...camps]);
  toast('Relatório de auditoria gerado.');
});
$('#review-create').addEventListener('click', createReview);
$('#review-items').addEventListener('click', async event => {
  const button = event.target.closest('[data-review-item]'); if (!button) return;
  button.disabled = true;
  try { await api(`/reviews/${button.dataset.campaignId}/items/${button.dataset.reviewItem}`, { method: 'PATCH', body: JSON.stringify({ decision: button.dataset.decision }) }); await openCampaign(Number(button.dataset.campaignId)); if (state.page === 'compliance') loadCompliance(); }
  catch (error) { toast(error.message); button.disabled = false; }
});

// Administração
$('#settings-save').addEventListener('click', saveSettings);
$$('input[name="schedule"]').forEach(radio => radio.addEventListener('change', renderNextRun));
$('#invite-email').addEventListener('input', event => { $('#invite-btn').disabled = !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(event.target.value.trim()); });
$('#invite-btn').addEventListener('click', async () => {
  const button = $('#invite-btn'); button.disabled = true;
  try {
    const result = await api('/users/invite', { method: 'POST', body: JSON.stringify({ email: $('#invite-email').value.trim(), role: $('#invite-role').value }) });
    $('#invite-email').value = '';
    $('#invite-text').textContent = `${result.user.email} foi cadastrado como ${ROLE_LABEL[result.user.role]}. Envie a senha temporária abaixo para o primeiro acesso.`;
    $('#invite-secret').textContent = result.temporaryPassword; $('#invite-modal').showModal();
    state.admin.users = await api('/users'); renderUsers();
  } catch (error) { toast(error.message, 5000); button.disabled = false; }
});
$('#invite-copy').addEventListener('click', async () => { try { await navigator.clipboard.writeText($('#invite-secret').textContent); toast('Senha copiada.'); } catch { toast('Selecione e copie a senha manualmente.'); } });
$('#invite-modal').addEventListener('close', () => { $('#invite-secret').textContent = ''; });
$('#users-rows').addEventListener('click', event => {
  const toggle = event.target.closest('[data-user-toggle]');
  if (toggle) { const user = state.admin.users.find(u => u.id === Number(toggle.dataset.userToggle)); toggle.disabled = true;
    api(`/users/${user.id}`, { method: 'PATCH', body: JSON.stringify({ active: !user.active }) }).then(async () => { state.admin.users = await api('/users'); renderUsers(); toast('Acesso do usuário atualizado.'); }).catch(error => { toast(error.message); toggle.disabled = false; }); return; }
  const remove = event.target.closest('[data-user-remove]');
  if (remove) { const user = state.admin.users.find(u => u.id === Number(remove.dataset.userRemove));
    confirmDialog({ title: 'Remover usuário?', ok: 'Remover usuário', text: `${user.name} (${user.email}) perderá o acesso à plataforma.`, onConfirm: async () => { await api(`/users/${user.id}`, { method: 'DELETE' }); state.admin.users = await api('/users'); renderUsers(); toast('Usuário removido.'); } }); }
});

/* ── session ────────────────────────────────────────────────────────── */
$('#login-form').addEventListener('submit', async event => {
  event.preventDefault(); const feedback = $('#login-feedback'); feedback.hidden = true;
  try {
    const session = await api('/auth/login', { method: 'POST', body: JSON.stringify({ email: $('#login-email').value, password: $('#login-password').value }) });
    state.token = session.token; state.user = session.user; localStorage.setItem('nexo.session', state.token);
    applyUser(); await initializePlatform();
  } catch (error) { feedback.textContent = error.message; feedback.hidden = false; }
});
function showLogin() {
  state.token = ''; state.user = null; localStorage.removeItem('nexo.session');
  document.body.classList.add('locked'); $('#login-screen').classList.remove('authenticated'); $('#login-password').value = '';
  $$('dialog[open]').forEach(dialog => dialog.close());
}
function applyUser() {
  document.body.classList.remove('locked'); $('#login-screen').classList.add('authenticated');
  $('#sb-user-name').textContent = state.user.name; $('#sb-user-email').textContent = state.user.email;
  $('#sb-avatar').textContent = (state.user.name.trim()[0] || 'U').toUpperCase();
  applyRoleVisibility();
}
async function initializePlatform() {
  await Promise.all([loadCredentialRequirements(), loadCredentials(), loadStatus(), loadSettings()]);
  navigate(canSee(state.page) ? state.page : 'dashboard');
}
// A tab left open keeps running the old bundle; compare the deployed bundle's ETag and reload when it changes.
let deployedVersion = null;
async function checkForUpdate() {
  try {
    const responses = await Promise.all(['./', 'app.js', 'modernist.css'].map(file => fetch(`${file}?probe=${Date.now()}`, { method: 'HEAD', cache: 'no-store' })));
    const version = responses.map(response => response.headers.get('ETag') || response.headers.get('Last-Modified') || '').join('|');
    if (!version.replaceAll('|', '')) return;
    if (deployedVersion && version !== deployedVersion && !$$('dialog[open]').length) { toast('Nova versão publicada. Atualizando…'); setTimeout(() => location.reload(), 800); return; }
    deployedVersion = version;
  } catch { /* offline: try again later */ }
}
setInterval(checkForUpdate, 30000);
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') checkForUpdate(); });
async function bootstrap() {
  paint(); checkForUpdate();
  if (!state.token) { showLogin(); return; }
  try { state.user = await api('/auth/me'); applyUser(); await initializePlatform(); } catch { showLogin(); }
}
bootstrap();
