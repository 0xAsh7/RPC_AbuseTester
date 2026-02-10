// ============================================
// Blockchain RPC Abuse Security Testing Tool
// Core Engine & Testing Modules
// ============================================

const APP_STATE = {
  targetUrl: '',
  protocol: 'ethereum',
  activeModule: 'discovery',
  isRunning: false,
  results: [],
  logs: [],
  stats: { critical: 0, major: 0, medium: 0, minor: 0, info: 0 }
};

// ── Severity Definitions ──
const SEVERITY = {
  CRITICAL: { label: 'Critical', class: 'severity-critical', icon: '🔴' },
  MAJOR: { label: 'Major', class: 'severity-major', icon: '🟠' },
  MEDIUM: { label: 'Medium', class: 'severity-medium', icon: '🟡' },
  MINOR: { label: 'Minor', class: 'severity-minor', icon: '🟢' },
  INFO: { label: 'Info', class: 'severity-info', icon: 'ℹ️' }
};

// ── RPC Client Core ──
class RPCClient {
  constructor(url, timeout = 8000) {
    this.url = url;
    this.timeout = timeout;
    this.requestId = 0;
  }

  async jsonRpc(method, params = []) {
    this.requestId++;
    const payload = { jsonrpc: '2.0', method, params, id: this.requestId };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(this.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal
      });
      clearTimeout(timer);
      const data = await res.json();
      return { success: true, status: res.status, data, method };
    } catch (err) {
      clearTimeout(timer);
      return { success: false, error: err.message, method };
    }
  }

  async httpGet(path = '') {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(this.url + path, { signal: controller.signal });
      clearTimeout(timer);
      const data = await res.json();
      return { success: true, status: res.status, data, path };
    } catch (err) {
      clearTimeout(timer);
      return { success: false, error: err.message, path };
    }
  }

  async timedRpc(method, params = []) {
    const start = performance.now();
    const result = await this.jsonRpc(method, params);
    result.latencyMs = Math.round(performance.now() - start);
    return result;
  }
}

// ── Module Definitions ──
const MODULES = {
  discovery: {
    name: 'Discovery & Fingerprint',
    icon: '🔍',
    desc: 'Identifies the node type, client version, network ID, and current block height using standard fingerprinting methods (Report §3.2).',
    methods: [
      { method: 'eth_blockNumber', params: [], desc: 'Current block height (hex)', severity: 'INFO' },
      { method: 'web3_clientVersion', params: [], desc: 'Client software & version', severity: 'INFO' },
      { method: 'net_version', params: [], desc: 'Network/Chain ID', severity: 'INFO' },
      { method: 'net_peerCount', params: [], desc: 'Connected peers (hex)', severity: 'INFO' },
      { method: 'eth_chainId', params: [], desc: 'EIP-155 chain identifier', severity: 'INFO' },
      { method: 'eth_syncing', params: [], desc: 'Sync status of the node', severity: 'INFO' },
      { method: 'eth_mining', params: [], desc: 'Whether node is mining', severity: 'INFO' },
      { method: 'eth_hashrate', params: [], desc: 'Mining hashrate', severity: 'INFO' }
    ]
  },
  enumeration: {
    name: 'Namespace Enumeration',
    icon: '📋',
    desc: 'Systematically probes all known API namespaces to map the attack surface. Methods returning -32601 are disabled; successful responses indicate exposure (Report §4.1-4.3).',
    methods: [
      // eth namespace
      { method: 'eth_accounts', params: [], desc: 'List local accounts', severity: 'MEDIUM' },
      { method: 'eth_coinbase', params: [], desc: 'Coinbase address', severity: 'MEDIUM' },
      { method: 'eth_gasPrice', params: [], desc: 'Current gas price', severity: 'INFO' },
      { method: 'eth_getCompilers', params: [], desc: 'Available compilers', severity: 'MINOR' },
      // admin namespace
      { method: 'admin_nodeInfo', params: [], desc: 'Full node info + enode URI', severity: 'CRITICAL' },
      { method: 'admin_peers', params: [], desc: 'Connected peer details', severity: 'CRITICAL' },
      { method: 'admin_datadir', params: [], desc: 'Node data directory path', severity: 'CRITICAL' },
      // debug namespace
      { method: 'debug_metrics', params: [true], desc: 'Internal metrics', severity: 'MAJOR' },
      { method: 'debug_stacks', params: [], desc: 'Goroutine stack traces', severity: 'MAJOR' },
      { method: 'debug_memStats', params: [], desc: 'Memory statistics', severity: 'MAJOR' },
      // personal namespace
      { method: 'personal_listAccounts', params: [], desc: 'List personal accounts', severity: 'CRITICAL' },
      { method: 'personal_listWallets', params: [], desc: 'List wallets with status', severity: 'CRITICAL' },
      // miner namespace
      { method: 'miner_getHashrate', params: [], desc: 'Miner hashrate', severity: 'MEDIUM' },
      // txpool namespace
      { method: 'txpool_status', params: [], desc: 'Pending/queued tx counts', severity: 'MEDIUM' },
      { method: 'txpool_content', params: [], desc: 'Full txpool contents', severity: 'MAJOR' },
      { method: 'txpool_inspect', params: [], desc: 'Txpool summary', severity: 'MEDIUM' },
      // web3 namespace
      { method: 'web3_sha3', params: ['0x68656c6c6f'], desc: 'SHA3/Keccak hash', severity: 'INFO' },
      // net namespace
      { method: 'net_listening', params: [], desc: 'P2P listening status', severity: 'INFO' }
    ]
  },
  wallet: {
    name: 'Wallet Audit',
    icon: '💰',
    desc: 'Checks for locally managed accounts, queries balances, and tests for unlocked wallet conditions that could allow unauthorized transaction signing (Report §5.1-5.2).',
    methods: [
      { method: 'eth_accounts', params: [], desc: 'List managed accounts', severity: 'MEDIUM' },
      { method: 'eth_coinbase', params: [], desc: 'Primary mining/staking address', severity: 'MEDIUM' },
      { method: 'personal_listAccounts', params: [], desc: 'Personal account list', severity: 'CRITICAL' },
      { method: 'personal_listWallets', params: [], desc: 'Wallet status & accounts', severity: 'CRITICAL' }
    ]
  },
  cors: {
    name: 'CORS & Vhost',
    icon: '🌐',
    desc: 'Tests for wildcard CORS configurations and missing virtual host filtering that could enable DNS rebinding attacks (Report §12.2).',
    methods: [] // Custom tests, not standard JSON-RPC
  },
  tendermint: {
    name: 'Tendermint Probe',
    icon: '⛓️',
    desc: 'Tests Tendermint/CometBFT-specific HTTP endpoints including unsafe methods like /dial_seeds and /unsafe_flush_mempool (Report §4.2, §6.3).',
    methods: [
      { path: '/status', desc: 'Node status & network info', severity: 'INFO' },
      { path: '/net_info', desc: 'Network peers & channels', severity: 'MEDIUM' },
      { path: '/validators', desc: 'Validator set & voting power', severity: 'MEDIUM' },
      { path: '/dump_consensus_state', desc: 'Internal consensus state', severity: 'MAJOR' },
      { path: '/consensus_state', desc: 'Current consensus round', severity: 'MEDIUM' },
      { path: '/unconfirmed_txs', desc: 'Mempool transactions', severity: 'MEDIUM' },
      { path: '/num_unconfirmed_txs', desc: 'Mempool tx count', severity: 'INFO' },
      { path: '/dial_seeds', desc: 'UNSAFE: inject seed peers', severity: 'CRITICAL' },
      { path: '/dial_peers', desc: 'UNSAFE: inject peers', severity: 'CRITICAL' },
      { path: '/unsafe_flush_mempool', desc: 'UNSAFE: flush mempool', severity: 'CRITICAL' }
    ]
  },
  solana: {
    name: 'Solana Probe',
    icon: '☀️',
    desc: 'Tests Solana-specific RPC methods for node health, version, cluster topology, and vote account visibility (Report §3.1).',
    methods: [
      { method: 'getHealth', params: [], desc: 'Node health status', severity: 'INFO' },
      { method: 'getVersion', params: [], desc: 'Solana version info', severity: 'INFO' },
      { method: 'getSlot', params: [], desc: 'Current slot number', severity: 'INFO' },
      { method: 'getBlockHeight', params: [], desc: 'Current block height', severity: 'INFO' },
      { method: 'getEpochInfo', params: [], desc: 'Current epoch details', severity: 'INFO' },
      { method: 'getVoteAccounts', params: [], desc: 'Validator vote accounts', severity: 'MEDIUM' },
      { method: 'getClusterNodes', params: [], desc: 'All cluster node IPs & ports', severity: 'MAJOR' },
      { method: 'getSupply', params: [], desc: 'Total SOL supply', severity: 'INFO' },
      { method: 'getRecentPerformanceSamples', params: [5], desc: 'TPS performance', severity: 'MINOR' },
      { method: 'getIdentity', params: [], desc: 'Node identity pubkey', severity: 'MEDIUM' }
    ]
  },
  resource: {
    name: 'Resource Exhaustion',
    icon: '⚡',
    desc: 'Measures response latency for increasingly heavy RPC calls to detect missing rate limits or gas caps on simulations (Report §10.3).',
    methods: [
      { method: 'eth_blockNumber', params: [], desc: 'Lightweight baseline call', severity: 'INFO', weight: 'Low' },
      { method: 'eth_gasPrice', params: [], desc: 'Low-cost gas query', severity: 'INFO', weight: 'Low' },
      { method: 'eth_getBlockByNumber', params: ['latest', false], desc: 'Block without tx bodies', severity: 'INFO', weight: 'Medium' },
      { method: 'eth_getBlockByNumber', params: ['latest', true], desc: 'Block with full tx objects', severity: 'MINOR', weight: 'Medium' },
      { method: 'eth_call', params: [{ to: '0x0000000000000000000000000000000000000000', data: '0x' }, 'latest'], desc: 'Empty eth_call simulation', severity: 'MINOR', weight: 'Medium' },
      { method: 'eth_getLogs', params: [{ fromBlock: '0x0', toBlock: 'latest', limit: 1 }], desc: 'Log query (may be rate-limited)', severity: 'MEDIUM', weight: 'High' }
    ]
  }
};

// ── Logging ──
function addLog(msg, type = 'info') {
  const time = new Date().toLocaleTimeString('en-US', { hour12: false });
  APP_STATE.logs.unshift({ time, msg, type });
  if (APP_STATE.logs.length > 200) APP_STATE.logs.pop();
  renderLogs();
}

function renderLogs() {
  const body = document.getElementById('logBody');
  if (!body) return;
  body.innerHTML = APP_STATE.logs.slice(0, 50).map(l =>
    `<div class="log-entry"><span class="log-time">${l.time}</span><span class="log-msg ${l.type}">${escapeHtml(l.msg)}</span></div>`
  ).join('');
}

function escapeHtml(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

// ── Result Classification ──
function classifyResult(methodDef, response) {
  if (!response.success) {
    return { status: 'error', statusLabel: 'Unreachable', severity: SEVERITY.INFO, detail: response.error };
  }
  const d = response.data;
  if (d && d.error) {
    const code = d.error.code;
    if (code === -32601) return { status: 'closed', statusLabel: 'Not Found (-32601)', severity: SEVERITY.INFO, detail: d.error.message };
    if (code === -32600) return { status: 'error', statusLabel: 'Invalid Req (-32600)', severity: SEVERITY.MINOR, detail: d.error.message };
    if (code === -32602) return { status: 'closed', statusLabel: 'Bad Params (-32602)', severity: SEVERITY.INFO, detail: d.error.message };
    return { status: 'error', statusLabel: `Error (${code})`, severity: SEVERITY.INFO, detail: d.error.message };
  }
  if (response.status === 401 || response.status === 403) {
    return { status: 'auth', statusLabel: 'Auth Required', severity: SEVERITY.INFO, detail: 'Protected but enabled' };
  }
  // Method is accessible
  const sev = SEVERITY[methodDef.severity] || SEVERITY.INFO;
  return { status: 'open', statusLabel: 'Accessible', severity: sev, detail: JSON.stringify(d?.result ?? d, null, 2) };
}

// ── Stats Update ──
function updateStats() {
  const s = { critical: 0, major: 0, medium: 0, minor: 0, info: 0 };
  APP_STATE.results.forEach(r => {
    if (r.status !== 'open') return;
    const label = r.severity.label.toLowerCase();
    if (s[label] !== undefined) s[label]++;
  });
  APP_STATE.stats = s;
  document.getElementById('statCritical').textContent = s.critical;
  document.getElementById('statMajor').textContent = s.major;
  document.getElementById('statMedium').textContent = s.medium;
  document.getElementById('statMinor').textContent = s.minor;
  document.getElementById('statInfo').textContent = s.info;
}

// ── Module Runners ──
async function runStandardModule(moduleKey) {
  const mod = MODULES[moduleKey];
  const client = new RPCClient(APP_STATE.targetUrl);
  const methods = mod.methods;
  const results = [];

  for (let i = 0; i < methods.length; i++) {
    updateProgress(i, methods.length, `Testing ${methods[i].method || methods[i].path}...`);
    addLog(`Probing: ${methods[i].method || methods[i].path}`, 'info');

    let response;
    if (methods[i].path) {
      response = await client.httpGet(methods[i].path);
    } else {
      response = await client.timedRpc(methods[i].method, methods[i].params);
    }

    const classification = classifyResult(methods[i], response);
    const result = {
      method: methods[i].method || methods[i].path,
      desc: methods[i].desc,
      ...classification,
      latencyMs: response.latencyMs || null,
      rawResponse: response.data || response.error,
      weight: methods[i].weight || null
    };
    results.push(result);

    if (result.status === 'open') {
      const sevLabel = result.severity.label;
      addLog(`✓ ${result.method} → ${sevLabel}: ${result.statusLabel}`, sevLabel === 'Critical' ? 'error' : sevLabel === 'Major' ? 'warning' : 'success');
    } else {
      addLog(`✗ ${result.method} → ${result.statusLabel}`, 'info');
    }

    await sleep(100);
  }

  updateProgress(methods.length, methods.length, 'Complete');
  return results;
}

async function runCORSModule() {
  const results = [];
  const url = APP_STATE.targetUrl;
  const payload = JSON.stringify({ jsonrpc: '2.0', method: 'eth_blockNumber', params: [], id: 1 });

  // Test 1: Standard request
  addLog('Testing standard JSON-RPC connectivity...', 'info');
  updateProgress(0, 4, 'Testing connectivity...');
  try {
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: payload });
    const headers = {};
    r.headers.forEach((v, k) => { headers[k] = v; });
    results.push({
      method: 'Standard Request', desc: 'Baseline connectivity check',
      status: r.ok ? 'open' : 'error', statusLabel: `HTTP ${r.status}`,
      severity: SEVERITY.INFO, detail: JSON.stringify(headers, null, 2), rawResponse: headers
    });
    addLog(`Baseline: HTTP ${r.status}`, 'success');
  } catch (e) {
    results.push({ method: 'Standard Request', desc: 'Baseline check', status: 'error', statusLabel: 'Failed', severity: SEVERITY.INFO, detail: e.message, rawResponse: e.message });
    addLog(`Baseline failed: ${e.message}`, 'error');
  }

  // Test 2: CORS with wildcard origin
  addLog('Testing CORS with evil origin...', 'info');
  updateProgress(1, 4, 'Testing CORS...');
  try {
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Origin': 'https://evil-attacker.com' }, body: payload });
    const acao = r.headers.get('access-control-allow-origin');
    const isWildcard = acao === '*';
    const isReflected = acao === 'https://evil-attacker.com';
    let sev = SEVERITY.INFO, label = 'Restricted';
    if (isWildcard) { sev = SEVERITY.MEDIUM; label = 'Wildcard CORS (*)'; }
    else if (isReflected) { sev = SEVERITY.MAJOR; label = 'Origin Reflected'; }
    else if (acao) { label = `CORS: ${acao}`; }
    results.push({
      method: 'CORS Origin Test', desc: 'Tests if CORS allows arbitrary origins',
      status: (isWildcard || isReflected) ? 'open' : 'closed', statusLabel: label,
      severity: sev, detail: `Access-Control-Allow-Origin: ${acao || 'not set'}`, rawResponse: { acao }
    });
    addLog(`CORS: ${label}`, isWildcard || isReflected ? 'warning' : 'success');
  } catch (e) {
    results.push({ method: 'CORS Origin Test', desc: 'CORS test', status: 'error', statusLabel: 'Blocked', severity: SEVERITY.INFO, detail: e.message, rawResponse: e.message });
    addLog(`CORS test blocked by browser: ${e.message}`, 'warning');
  }

  // Test 3: Preflight OPTIONS
  addLog('Testing CORS preflight...', 'info');
  updateProgress(2, 4, 'Testing preflight...');
  try {
    const r = await fetch(url, { method: 'OPTIONS', headers: { 'Origin': 'https://evil-attacker.com', 'Access-Control-Request-Method': 'POST' } });
    const allowMethods = r.headers.get('access-control-allow-methods');
    const allowHeaders = r.headers.get('access-control-allow-headers');
    results.push({
      method: 'CORS Preflight', desc: 'OPTIONS preflight response analysis',
      status: r.ok ? 'open' : 'closed', statusLabel: `HTTP ${r.status}`,
      severity: r.ok ? SEVERITY.MINOR : SEVERITY.INFO,
      detail: `Methods: ${allowMethods || 'none'}\nHeaders: ${allowHeaders || 'none'}`,
      rawResponse: { allowMethods, allowHeaders }
    });
    addLog(`Preflight: HTTP ${r.status}`, 'info');
  } catch (e) {
    results.push({ method: 'CORS Preflight', desc: 'Preflight test', status: 'error', statusLabel: 'Blocked', severity: SEVERITY.INFO, detail: e.message, rawResponse: e.message });
  }

  // Test 4: Content-Type bypass
  addLog('Testing Content-Type bypass...', 'info');
  updateProgress(3, 4, 'Testing content-type bypass...');
  try {
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: payload });
    const data = await r.json();
    const bypassed = !data.error;
    results.push({
      method: 'Content-Type Bypass', desc: 'Tests if text/plain bypasses CORS preflight',
      status: bypassed ? 'open' : 'closed', statusLabel: bypassed ? 'Bypassed' : 'Enforced',
      severity: bypassed ? SEVERITY.MEDIUM : SEVERITY.INFO,
      detail: JSON.stringify(data, null, 2), rawResponse: data
    });
    addLog(`Content-Type bypass: ${bypassed ? 'VULNERABLE' : 'Enforced'}`, bypassed ? 'warning' : 'success');
  } catch (e) {
    results.push({ method: 'Content-Type Bypass', desc: 'CT bypass', status: 'error', statusLabel: 'Failed', severity: SEVERITY.INFO, detail: e.message, rawResponse: e.message });
  }

  updateProgress(4, 4, 'Complete');
  return results;
}

async function runWalletAudit() {
  const results = await runStandardModule('wallet');
  // If eth_accounts returned addresses, query balances
  const accountResult = results.find(r => r.method === 'eth_accounts' && r.status === 'open');
  if (accountResult && accountResult.rawResponse?.result) {
    const accounts = accountResult.rawResponse.result;
    if (Array.isArray(accounts) && accounts.length > 0) {
      addLog(`Found ${accounts.length} accounts! Querying balances...`, 'warning');
      const client = new RPCClient(APP_STATE.targetUrl);
      for (const addr of accounts.slice(0, 20)) {
        const balRes = await client.jsonRpc('eth_getBalance', [addr, 'latest']);
        if (balRes.success && balRes.data?.result) {
          const weiHex = balRes.data.result;
          const ethVal = parseInt(weiHex, 16) / 1e18;
          const sev = ethVal > 0 ? SEVERITY.CRITICAL : SEVERITY.MEDIUM;
          results.push({
            method: `eth_getBalance(${addr.slice(0, 10)}...)`,
            desc: `Balance: ${ethVal.toFixed(6)} ETH`,
            status: 'open', statusLabel: ethVal > 0 ? 'FUNDED' : 'Empty',
            severity: sev, detail: `Address: ${addr}\nBalance: ${ethVal} ETH\nWei: ${weiHex}`,
            rawResponse: balRes.data
          });
          addLog(`${addr.slice(0, 10)}... → ${ethVal.toFixed(6)} ETH ${ethVal > 0 ? '⚠️ FUNDED!' : ''}`, ethVal > 0 ? 'error' : 'info');
        }
        await sleep(100);
      }
    }
  }
  return results;
}

// ── UI Rendering ──
function switchModule(key) {
  APP_STATE.activeModule = key;
  document.querySelectorAll('.module-nav-item').forEach(el => el.classList.remove('active'));
  document.querySelector(`[data-module="${key}"]`)?.classList.add('active');
  renderModuleContent();
}

function renderModuleContent() {
  const key = APP_STATE.activeModule;
  const mod = MODULES[key];
  const panel = document.getElementById('contentBody');
  const title = document.getElementById('contentTitle');
  title.innerHTML = `<span class="module-icon">${mod.icon}</span> ${mod.name}`;

  const moduleResults = APP_STATE.results.filter(r => r._module === key);

  let html = `<div class="module-desc">${mod.desc}</div>`;
  html += `<div class="test-progress" id="progressArea" style="display:none">
    <div class="progress-bar-container"><div class="progress-bar" id="progressBar" style="width:0%"></div></div>
    <div class="progress-text" id="progressText">Ready</div>
  </div>`;

  if (moduleResults.length === 0) {
    html += `<div class="empty-state">
      <div class="empty-icon">🛡️</div>
      <h3>No results yet</h3>
      <p>Enter a target RPC URL above and click "Run Scan" or use the module-specific "Run" button to start testing.</p>
    </div>`;
  } else {
    html += buildResultsTable(moduleResults, key);
  }

  panel.innerHTML = html;
}

function buildResultsTable(results, moduleKey) {
  const isResource = moduleKey === 'resource';
  let html = `<div class="results-container"><table class="results-table"><thead><tr>
    <th>Method</th><th>Description</th><th>Status</th><th>Severity</th>
    ${isResource ? '<th>Latency</th><th>Weight</th>' : '<th>Response</th>'}
  </tr></thead><tbody>`;

  results.forEach((r, i) => {
    html += `<tr class="fade-in" style="animation-delay:${i * 40}ms">
      <td><span class="method-name">${escapeHtml(r.method)}</span></td>
      <td style="color:var(--text-secondary);font-size:0.8rem">${escapeHtml(r.desc)}</td>
      <td><span class="status status-${r.status}"><span class="status-dot"></span>${r.statusLabel}</span></td>
      <td><span class="severity ${r.severity.class}">${r.severity.icon} ${r.severity.label}</span></td>`;

    if (isResource) {
      html += `<td><span class="method-name">${r.latencyMs != null ? r.latencyMs + 'ms' : '—'}</span></td>`;
      html += `<td style="color:var(--text-muted);font-size:0.8rem">${r.weight || '—'}</td>`;
    } else {
      const preview = typeof r.detail === 'string' ? r.detail.slice(0, 80) : '';
      html += `<td><span class="response-preview" onclick="showDetail(${i},'${APP_STATE.activeModule}')" title="Click to expand">${escapeHtml(preview)}</span></td>`;
    }
    html += `</tr>`;
  });

  html += '</tbody></table></div>';
  return html;
}

function updateProgress(current, total, text) {
  const area = document.getElementById('progressArea');
  const bar = document.getElementById('progressBar');
  const txt = document.getElementById('progressText');
  if (!area) return;
  area.style.display = 'block';
  const pct = total > 0 ? Math.round((current / total) * 100) : 0;
  bar.style.width = pct + '%';
  txt.textContent = `${text} (${pct}%)`;
}

function updateNavBadges() {
  Object.keys(MODULES).forEach(key => {
    const modResults = APP_STATE.results.filter(r => r._module === key && r.status === 'open');
    const badge = document.querySelector(`[data-module="${key}"] .badge`);
    if (!badge) return;
    const critCount = modResults.filter(r => r.severity === SEVERITY.CRITICAL || r.severity === SEVERITY.MAJOR).length;
    if (critCount > 0) {
      badge.textContent = critCount;
      badge.className = 'badge badge-critical';
    } else if (modResults.length > 0) {
      badge.textContent = modResults.length;
      badge.className = 'badge badge-ok';
    } else {
      badge.textContent = '';
    }
  });
}

// ── Main Run Function ──
async function runModule(moduleKey) {
  if (APP_STATE.isRunning) return;
  const url = getTargetUrl();
  if (!url) { alert('Please enter a target RPC URL or IP address'); return; }
  APP_STATE.targetUrl = url;
  APP_STATE.isRunning = true;
  toggleRunButton(true);

  // Clear previous results for this module
  APP_STATE.results = APP_STATE.results.filter(r => r._module !== moduleKey);
  switchModule(moduleKey);
  addLog(`━━━ Starting ${MODULES[moduleKey].name} scan on ${url} ━━━`, 'info');

  let results;
  try {
    if (moduleKey === 'cors') results = await runCORSModule();
    else if (moduleKey === 'wallet') results = await runWalletAudit();
    else results = await runStandardModule(moduleKey);

    results.forEach(r => { r._module = moduleKey; });
    APP_STATE.results.push(...results);
    addLog(`━━━ ${MODULES[moduleKey].name} complete: ${results.length} tests ━━━`, 'success');
  } catch (e) {
    addLog(`Error: ${e.message}`, 'error');
  }

  APP_STATE.isRunning = false;
  toggleRunButton(false);
  updateStats();
  updateNavBadges();
  renderModuleContent();
}

async function runAllModules() {
  if (APP_STATE.isRunning) return;
  const url = getTargetUrl();
  if (!url) { alert('Please enter a target RPC URL or IP address'); return; }

  const protocol = getProtocol();
  let modulesToRun;
  if (protocol === 'ethereum') modulesToRun = ['discovery', 'enumeration', 'wallet', 'cors', 'resource'];
  else if (protocol === 'tendermint') modulesToRun = ['tendermint'];
  else if (protocol === 'solana') modulesToRun = ['solana'];
  else modulesToRun = Object.keys(MODULES);

  for (const key of modulesToRun) {
    await runModule(key);
    await sleep(300);
  }
}

// ── Report Generation ──
function generateReport() {
  const report = {
    tool: 'Blockchain RPC Abuse Security Tester',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    target: APP_STATE.targetUrl,
    protocol: document.getElementById('protocolSelect')?.value || 'unknown',
    summary: { ...APP_STATE.stats, totalFindings: APP_STATE.results.filter(r => r.status === 'open').length },
    findings: APP_STATE.results.map(r => ({
      module: r._module,
      method: r.method,
      description: r.desc,
      status: r.statusLabel,
      severity: r.severity.label,
      detail: r.detail,
      latencyMs: r.latencyMs
    }))
  };

  const modal = document.getElementById('reportModal');
  document.getElementById('reportJson').textContent = JSON.stringify(report, null, 2);
  modal.classList.add('active');
}

function downloadReport() {
  const json = document.getElementById('reportJson').textContent;
  const blob = new Blob([json], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `rpc-audit-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

function closeModal() {
  document.getElementById('reportModal').classList.remove('active');
}

// ── Detail View ──
function showDetail(idx, moduleKey) {
  const results = APP_STATE.results.filter(r => r._module === moduleKey);
  const r = results[idx];
  if (!r) return;
  const overlay = document.getElementById('detailOverlay');
  document.getElementById('detailTitle').textContent = r.method;
  document.getElementById('detailContent').textContent = typeof r.detail === 'string' ? r.detail : JSON.stringify(r.rawResponse, null, 2);
  overlay.classList.add('active');
}

function closeDetail() {
  document.getElementById('detailOverlay').classList.remove('active');
}

// ── Utilities ──
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function toggleRunButton(running) {
  const btns = [document.getElementById('runBtn'), document.getElementById('runAllBtn'), document.getElementById('runAllBtn2')];
  btns.forEach(btn => {
    if (!btn) return;
    btn.disabled = running;
    if (btn.id === 'runBtn') btn.innerHTML = running ? '<span class="spinner"></span> Scanning...' : '▶ Run Module';
    else btn.innerHTML = running ? '<span class="spinner"></span> Scanning...' : '⚡ Full Scan';
  });
}

function setQuickTarget(url) {
  document.getElementById('targetUrl').value = url;
  setInputMode('url');
}

// ── Input Mode Toggle ──
let currentInputMode = 'url';

function setInputMode(mode) {
  currentInputMode = mode;
  const urlRow = document.getElementById('urlInputRow');
  const ipRow = document.getElementById('ipInputRow');
  const urlChips = document.getElementById('urlChips');
  const portChips = document.getElementById('portChips');
  const modeUrl = document.getElementById('modeUrl');
  const modeIp = document.getElementById('modeIp');

  if (mode === 'url') {
    urlRow.style.display = 'flex';
    ipRow.style.display = 'none';
    urlChips.style.display = 'flex';
    portChips.style.display = 'none';
    modeUrl.classList.add('active');
    modeIp.classList.remove('active');
  } else {
    urlRow.style.display = 'none';
    ipRow.style.display = 'flex';
    urlChips.style.display = 'none';
    portChips.style.display = 'flex';
    modeUrl.classList.remove('active');
    modeIp.classList.add('active');
  }
}

function setPort(port) {
  document.getElementById('targetPort').value = port;
  // Auto-select protocol based on port
  const sel = document.getElementById('protocolSelect2');
  if (port === '8545' || port === '8546' || port === '8551') sel.value = 'ethereum';
  else if (port === '26657') sel.value = 'tendermint';
  else if (port === '8899' || port === '8900') sel.value = 'solana';
}

function getTargetUrl() {
  if (currentInputMode === 'url') {
    return document.getElementById('targetUrl').value.trim();
  }
  const scheme = document.getElementById('schemeSelect').value;
  const ip = document.getElementById('targetIp').value.trim();
  const port = document.getElementById('targetPort').value.trim();
  if (!ip) return '';
  return `${scheme}://${ip}${port ? ':' + port : ''}`;
}

function getProtocol() {
  if (currentInputMode === 'url') return document.getElementById('protocolSelect').value;
  return document.getElementById('protocolSelect2').value;
}

// ── Shodan Panel ──
function toggleShodan() {
  const body = document.getElementById('shodanBody');
  const toggle = document.getElementById('shodanToggle');
  body.classList.toggle('open');
  toggle.classList.toggle('open');
}

function copyShodanQuery(el) {
  const code = el.querySelector('code');
  const text = code.textContent;
  navigator.clipboard.writeText(text).then(() => {
    el.classList.add('copied');
    setTimeout(() => el.classList.remove('copied'), 1500);
  });
}

// ============================================
// Scanner Module — Built-in RPC Discovery
// ============================================

const SCAN_STATE = {
  isScanning: false,
  discovered: [],
  scanned: 0,
  total: 0,
  scannerTab: 'manual', // 'manual' or 'shodan'
  filters: {
    protocol: 'all',    // 'all', 'ethereum', 'tendermint', 'solana'
    hasBalance: false,
    hasAccounts: false,
    vulnerableOnly: false
  },
  enriching: false
};

const SCAN_PORTS = [
  { port: 8545, label: 'ETH RPC', protocol: 'ethereum', checked: true },
  { port: 8546, label: 'ETH WS', protocol: 'ethereum', checked: false },
  { port: 8551, label: 'Engine API', protocol: 'ethereum', checked: false },
  { port: 26657, label: 'Tendermint', protocol: 'tendermint', checked: true },
  { port: 8899, label: 'Solana RPC', protocol: 'solana', checked: true },
  { port: 8900, label: 'Solana WS', protocol: 'solana', checked: false }
];

const BLOCKCHAIN_PORTS = [8545, 8546, 8551, 26657, 8899, 8900, 30303];

const SHODAN_EXAMPLE_QUERIES = [
  { query: 'port:8545 jsonrpc', desc: 'Ethereum JSON-RPC nodes', protocol: 'ethereum' },
  { query: 'port:8545 "eth_blockNumber"', desc: 'Confirmed Ethereum RPC', protocol: 'ethereum' },
  { query: '"geth" port:8545', desc: 'Geth nodes specifically', protocol: 'ethereum' },
  { query: 'port:8545 "Hyperledger Besu"', desc: 'Besu nodes', protocol: 'ethereum' },
  { query: 'port:26657 tendermint', desc: 'Tendermint/CometBFT nodes', protocol: 'tendermint' },
  { query: 'port:26657 "node_info"', desc: 'Exposed Tendermint status', protocol: 'tendermint' },
  { query: 'port:8899', desc: 'Solana RPC nodes', protocol: 'solana' },
  { query: 'port:8899 "getHealth"', desc: 'Confirmed Solana RPC', protocol: 'solana' },
  { query: '"-32601" jsonrpc', desc: 'Error-leaking JSON-RPC', protocol: 'ethereum' },
  { query: 'port:8551 "engine"', desc: 'Ethereum Engine API', protocol: 'ethereum' }
];

// ── Shodan API Key Management ──
function getShodanApiKey() {
  return localStorage.getItem('shodan_api_key') || '';
}

function saveShodanApiKey(key) {
  if (key) localStorage.setItem('shodan_api_key', key.trim());
  else localStorage.removeItem('shodan_api_key');
}

// ── CORS Proxy (Shodan API doesn't support browser CORS) ──
const CORS_PROXIES = [
  url => `https://corsproxy.io/?url=${encodeURIComponent(url)}`,
  url => `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
  url => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(url)}`
];

async function fetchWithCORS(url, options = {}, timeout = 15000) {
  for (let i = 0; i < CORS_PROXIES.length; i++) {
    const proxiedUrl = CORS_PROXIES[i](url);
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), timeout);
      const res = await fetch(proxiedUrl, { ...options, signal: ctrl.signal });
      clearTimeout(timer);
      // Some proxies return 200 but with error body — check for proxy errors
      if (res.ok || res.status === 401 || res.status === 403 || res.status === 429) return res;
      throw new Error(`Proxy returned HTTP ${res.status}`);
    } catch (e) {
      if (i === CORS_PROXIES.length - 1) throw new Error(`All CORS proxies failed. Last error: ${e.message}`);
      addLog(`CORS proxy ${i + 1} failed, trying next...`, 'warning');
    }
  }
}

// ── Shodan API Search ──
async function shodanSearch(query, apiKey) {
  // First check if key has query credits
  addLog('Checking Shodan API key & query credits...', 'info');
  try {
    const infoRes = await fetchWithCORS(`https://api.shodan.io/api-info?key=${encodeURIComponent(apiKey)}`);
    if (infoRes.ok) {
      const info = await infoRes.json();
      addLog(`Shodan plan: ${info.plan || 'free'} | Query credits: ${info.query_credits ?? 0} | Scan credits: ${info.scan_credits ?? 0}`, 'info');
      if ((info.query_credits ?? 0) <= 0) {
        throw new Error('No query credits remaining. Free Shodan accounts start with 0 search credits. You need a paid plan or purchased credits for the Search API. Use the Manual IPs tab with InternetDB pre-filter instead (completely free).');
      }
    }
  } catch (e) {
    if (e.message.includes('No query credits')) throw e;
    addLog('Could not verify credits, attempting search anyway...', 'warning');
  }

  const url = `https://api.shodan.io/shodan/host/search?key=${encodeURIComponent(apiKey)}&query=${encodeURIComponent(query)}&minify=true`;
  addLog('Routing through CORS proxy...', 'info');
  try {
    const res = await fetchWithCORS(url);
    if (res.status === 401) throw new Error('Invalid API key. Get a free key at account.shodan.io');
    if (res.status === 403) throw new Error('Access denied (HTTP 403). Your Shodan plan likely has 0 query credits. The Search API requires a paid plan or purchased credits. Use the Manual IPs tab with InternetDB pre-filter as a free alternative.');
    if (res.status === 429) throw new Error('Rate limited. Try again later.');
    if (!res.ok) throw new Error(`Shodan API error: HTTP ${res.status}`);
    const data = await res.json();
    return data;
  } catch (e) {
    throw e;
  }
}

// ── Shodan Host Lookup (FREE — works with any API key) ──
async function shodanHostLookup(ip, apiKey) {
  try {
    const res = await fetchWithCORS(
      `https://api.shodan.io/shodan/host/${ip}?key=${encodeURIComponent(apiKey)}&minify=true`,
      {}, 10000
    );
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    return null;
  }
}


// ── Shodan InternetDB (Free, no key — has native CORS) ──
async function internetDBLookup(ip) {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5000);
    // InternetDB supports CORS natively, try direct first
    const res = await fetch(`https://internetdb.shodan.io/${ip}`, { signal: ctrl.signal });
    clearTimeout(timer);
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    // Fallback to CORS proxy if direct fails
    try {
      const res = await fetchWithCORS(`https://internetdb.shodan.io/${ip}`, {}, 5000);
      if (!res.ok) return null;
      return await res.json();
    } catch (e2) {
      return null;
    }
  }
}


// ── CIDR Parser ──
function parseCIDR(cidr) {
  const parts = cidr.trim().split('/');
  if (parts.length !== 2) return [cidr.trim()];
  const prefix = parseInt(parts[1]);
  if (isNaN(prefix) || prefix < 16 || prefix > 32) return [parts[0]];
  const octets = parts[0].split('.').map(Number);
  if (octets.length !== 4 || octets.some(o => isNaN(o) || o < 0 || o > 255)) return [];
  const baseIp = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
  const mask = ~((1 << (32 - prefix)) - 1);
  const network = baseIp & mask;
  const count = 1 << (32 - prefix);
  const ips = [];
  const start = prefix < 31 ? 1 : 0;
  const end = prefix < 31 ? count - 1 : count;
  for (let i = start; i < end && ips.length < 1024; i++) {
    const ip = (network + i) >>> 0;
    ips.push(`${(ip >> 24) & 255}.${(ip >> 16) & 255}.${(ip >> 8) & 255}.${ip & 255}`);
  }
  return ips;
}

function parseIPInput(text) {
  const lines = text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  const ips = [];
  for (const line of lines) {
    if (line.includes('/')) {
      ips.push(...parseCIDR(line));
    } else if (line.match(/^[\d.]+$/)) {
      ips.push(line);
    } else if (line.includes('-')) {
      const m = line.match(/^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$/);
      if (m) {
        const base = m[1];
        const start = parseInt(m[2]), end = Math.min(parseInt(m[3]), 255);
        for (let i = start; i <= end && ips.length < 1024; i++) ips.push(base + i);
      }
    }
  }
  return [...new Set(ips)];
}

// ── Probe Functions ──
async function probeEndpoint(ip, port, timeout = 5000) {
  const url = `http://${ip}:${port}`;
  const start = performance.now();

  // Try Ethereum JSON-RPC
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeout);
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'eth_blockNumber', params: [], id: 1 }),
      signal: ctrl.signal
    });
    clearTimeout(timer);
    const data = await res.json();
    const latency = Math.round(performance.now() - start);
    if (data.jsonrpc === '2.0' && data.result) {
      let clientVersion = 'Unknown';
      try {
        const ctrl2 = new AbortController();
        const t2 = setTimeout(() => ctrl2.abort(), 3000);
        const r2 = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', method: 'web3_clientVersion', params: [], id: 2 }),
          signal: ctrl2.signal
        });
        clearTimeout(t2);
        const d2 = await r2.json();
        if (d2.result) clientVersion = d2.result;
      } catch (e) { }
      return { alive: true, ip, port, protocol: 'Ethereum', client: clientVersion, blockHeight: data.result, latency, url };
    }
    if (data.result === 'ok' || typeof data.result === 'number') {
      return { alive: true, ip, port, protocol: 'Solana', client: 'Solana RPC', blockHeight: String(data.result), latency, url };
    }
  } catch (e) { }

  // Try Solana getHealth
  if (port === 8899 || port === 8900) {
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), timeout);
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', method: 'getHealth', params: [], id: 1 }),
        signal: ctrl.signal
      });
      clearTimeout(timer);
      const data = await res.json();
      const latency = Math.round(performance.now() - start);
      if (data.result === 'ok' || data.result) {
        let version = 'Unknown';
        try {
          const ctrl2 = new AbortController();
          const t2 = setTimeout(() => ctrl2.abort(), 3000);
          const r2 = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ jsonrpc: '2.0', method: 'getVersion', params: [], id: 2 }),
            signal: ctrl2.signal
          });
          clearTimeout(t2);
          const d2 = await r2.json();
          if (d2.result) version = d2.result['solana-core'] || JSON.stringify(d2.result);
        } catch (e) { }
        return { alive: true, ip, port, protocol: 'Solana', client: version, blockHeight: data.result, latency, url };
      }
    } catch (e) { }
  }

  // Try Tendermint HTTP
  if (port === 26657) {
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), timeout);
      const res = await fetch(`${url}/status`, { signal: ctrl.signal });
      clearTimeout(timer);
      const data = await res.json();
      const latency = Math.round(performance.now() - start);
      if (data.result && data.result.node_info) {
        const ni = data.result.node_info;
        return {
          alive: true, ip, port, protocol: 'Tendermint',
          client: `${ni.moniker || 'Unknown'} (${ni.version || '?'})`,
          blockHeight: data.result.sync_info?.latest_block_height || '?',
          latency, url
        };
      }
    } catch (e) { }
  }

  return { alive: false, ip, port };
}

// ── Parallel Scanner with Semaphore ──
async function runScan() {
  if (SCAN_STATE.isScanning) return;
  const ipText = document.getElementById('scanIpInput')?.value;
  if (!ipText || !ipText.trim()) { alert('Please enter IP addresses or CIDR ranges'); return; }

  const ips = parseIPInput(ipText);
  if (ips.length === 0) { alert('No valid IPs parsed from input'); return; }
  if (ips.length > 1024) { alert('Maximum 1024 IPs per scan. Use a narrower CIDR range.'); return; }

  const selectedPorts = getSelectedPorts();
  if (selectedPorts.length === 0) { alert('Select at least one port to scan'); return; }

  const concurrency = parseInt(document.getElementById('scanConcurrency')?.value || '10');
  const timeout = parseInt(document.getElementById('scanTimeout')?.value || '5') * 1000;

  // Check if InternetDB pre-filter is enabled
  const useInternetDB = document.getElementById('useInternetDB')?.checked;

  SCAN_STATE.isScanning = true;
  SCAN_STATE.discovered = [];
  SCAN_STATE.scanned = 0;

  let filteredTasks = [];

  if (useInternetDB && ips.length > 10) {
    // Pre-filter using InternetDB
    addLog(`━━━ Pre-filtering ${ips.length} IPs using Shodan InternetDB (free, no key needed)... ━━━`, 'info');
    SCAN_STATE.total = ips.length;
    updateScanUI();

    let checked = 0;
    const batchSize = 10;
    for (let i = 0; i < ips.length; i += batchSize) {
      const batch = ips.slice(i, i + batchSize);
      const results = await Promise.all(batch.map(async (ip) => {
        const info = await internetDBLookup(ip);
        checked++;
        SCAN_STATE.scanned = checked;
        if (checked % 10 === 0) updateScanProgress();
        if (info && info.ports) {
          const matchingPorts = selectedPorts.filter(p => info.ports.includes(p));
          if (matchingPorts.length > 0) {
            addLog(`InternetDB: ${ip} has blockchain ports: ${matchingPorts.join(', ')}`, 'success');
            return matchingPorts.map(port => ({ ip, port }));
          }
        }
        return [];
      }));
      filteredTasks.push(...results.flat());
      if (!SCAN_STATE.isScanning) break;
    }
    addLog(`InternetDB pre-filter: ${filteredTasks.length} targets from ${ips.length} IPs`, 'info');
  } else {
    for (const ip of ips) {
      for (const port of selectedPorts) {
        filteredTasks.push({ ip, port });
      }
    }
  }

  if (filteredTasks.length === 0) {
    SCAN_STATE.isScanning = false;
    SCAN_STATE.total = 0;
    addLog('No targets to probe after filtering.', 'warning');
    updateScanUI();
    renderScannerContent();
    return;
  }

  // Now probe the filtered targets
  SCAN_STATE.scanned = 0;
  SCAN_STATE.total = filteredTasks.length;
  addLog(`━━━ Probing ${filteredTasks.length} targets (concurrency: ${concurrency}) ━━━`, 'info');
  updateScanUI();

  let idx = 0;
  const workers = Array.from({ length: Math.min(concurrency, filteredTasks.length) }, async () => {
    while (idx < filteredTasks.length && SCAN_STATE.isScanning) {
      const task = filteredTasks[idx++];
      try {
        const result = await probeEndpoint(task.ip, task.port, timeout);
        if (result.alive) {
          SCAN_STATE.discovered.push(result);
          addLog(`✓ FOUND: ${result.ip}:${result.port} — ${result.protocol} (${result.client})`, 'success');
        }
      } catch (e) { }
      SCAN_STATE.scanned++;
      if (SCAN_STATE.scanned % 5 === 0 || SCAN_STATE.scanned === SCAN_STATE.total) {
        updateScanProgress();
      }
    }
  });

  await Promise.all(workers);

  SCAN_STATE.isScanning = false;
  addLog(`━━━ Scanner complete: ${SCAN_STATE.discovered.length} endpoints found out of ${SCAN_STATE.total} probed ━━━`, SCAN_STATE.discovered.length > 0 ? 'success' : 'warning');

  // Auto-test if enabled
  const autoTest = document.getElementById('autoTestToggle')?.checked;
  if (autoTest && SCAN_STATE.discovered.length > 0) {
    await runAutoTest();
  }

  updateScanUI();
  renderScannerContent();
}

// ── Shodan Query Search & Auto-Scan ──
async function runShodanQueryScan() {
  if (SCAN_STATE.isScanning) return;
  const apiKey = document.getElementById('shodanApiKeyInput')?.value?.trim() || getShodanApiKey();
  const query = document.getElementById('shodanQueryInput')?.value?.trim();

  if (!apiKey) { alert('Please enter your Shodan API key. Get a free one at account.shodan.io'); return; }
  if (!query) { alert('Please enter a search query'); return; }

  saveShodanApiKey(apiKey);
  SCAN_STATE.isScanning = true;
  SCAN_STATE.discovered = [];
  SCAN_STATE.scanned = 0;
  SCAN_STATE.total = 0;
  updateScanUI();

  addLog(`━━━ Shodan API search: "${query}" ━━━`, 'info');

  try {
    const data = await shodanSearch(query, apiKey);
    const matches = data.matches || [];
    addLog(`Shodan returned ${matches.length} results (total available: ${data.total || '?'})`, 'success');

    if (matches.length === 0) {
      SCAN_STATE.isScanning = false;
      addLog('No results from Shodan. Try a different query.', 'warning');
      updateScanUI();
      renderScannerContent();
      return;
    }

    // Extract unique IP:Port pairs
    const targets = [];
    const seen = new Set();
    for (const m of matches) {
      const key = `${m.ip_str}:${m.port}`;
      if (!seen.has(key)) {
        seen.add(key);
        targets.push({ ip: m.ip_str, port: m.port, org: m.org || '', product: m.product || '' });
      }
    }

    addLog(`Found ${targets.length} unique targets. Probing for RPC services...`, 'info');

    // Probe each target
    SCAN_STATE.total = targets.length;
    const concurrency = parseInt(document.getElementById('scanConcurrency2')?.value || '10');
    const timeout = parseInt(document.getElementById('scanTimeout2')?.value || '5') * 1000;

    let tidx = 0;
    const workers = Array.from({ length: Math.min(concurrency, targets.length) }, async () => {
      while (tidx < targets.length && SCAN_STATE.isScanning) {
        const t = targets[tidx++];
        try {
          const result = await probeEndpoint(t.ip, t.port, timeout);
          if (result.alive) {
            result.org = t.org;
            SCAN_STATE.discovered.push(result);
            addLog(`✓ FOUND: ${result.ip}:${result.port} — ${result.protocol} (${result.client}) [${t.org}]`, 'success');
          }
        } catch (e) { }
        SCAN_STATE.scanned++;
        if (SCAN_STATE.scanned % 3 === 0 || SCAN_STATE.scanned === SCAN_STATE.total) {
          updateScanProgress();
        }
      }
    });

    await Promise.all(workers);

    addLog(`━━━ Shodan scan complete: ${SCAN_STATE.discovered.length} live endpoints from ${targets.length} results ━━━`,
      SCAN_STATE.discovered.length > 0 ? 'success' : 'warning');

    // Auto-test if enabled
    const autoTest = document.getElementById('autoTestToggle2')?.checked;
    if (autoTest && SCAN_STATE.discovered.length > 0) {
      await runAutoTest();
    }

  } catch (e) {
    addLog(`Shodan API error: ${e.message}`, 'error');
  }

  SCAN_STATE.isScanning = false;
  updateScanUI();
  renderScannerContent();
}

// ── Auto-Test Pipeline ──
async function runAutoTest() {
  addLog(`━━━ Auto-Test: Running vulnerability scans on ${SCAN_STATE.discovered.length} endpoints ━━━`, 'warning');

  for (let i = 0; i < SCAN_STATE.discovered.length && i < 20; i++) {
    const endpoint = SCAN_STATE.discovered[i];
    const proto = endpoint.protocol.toLowerCase();

    APP_STATE.targetUrl = endpoint.url;
    addLog(`Auto-testing [${i + 1}/${Math.min(SCAN_STATE.discovered.length, 20)}]: ${endpoint.url} (${proto})`, 'info');

    try {
      let modulesToRun;
      if (proto === 'ethereum') modulesToRun = ['enumeration', 'wallet', 'cors'];
      else if (proto === 'tendermint') modulesToRun = ['tendermint'];
      else if (proto === 'solana') modulesToRun = ['solana'];
      else modulesToRun = ['discovery'];

      for (const modKey of modulesToRun) {
        APP_STATE.results = APP_STATE.results.filter(r => r._module !== modKey || r._targetUrl !== endpoint.url);

        let results;
        if (modKey === 'cors') results = await runCORSModule();
        else if (modKey === 'wallet') results = await runWalletAudit();
        else results = await runStandardModule(modKey);

        results.forEach(r => { r._module = modKey; r._targetUrl = endpoint.url; });
        APP_STATE.results.push(...results);
        await sleep(200);
      }

      // Count findings for this endpoint
      const findings = APP_STATE.results.filter(r => r._targetUrl === endpoint.url && r.status === 'open');
      const criticals = findings.filter(r => r.severity === SEVERITY.CRITICAL || r.severity === SEVERITY.MAJOR);
      if (criticals.length > 0) {
        endpoint.autoTestStatus = 'vulnerable';
        endpoint.findings = `${criticals.length} critical/major`;
        addLog(`⚠️ ${endpoint.url}: ${criticals.length} critical/major findings!`, 'error');
      } else if (findings.length > 0) {
        endpoint.autoTestStatus = 'findings';
        endpoint.findings = `${findings.length} findings`;
      } else {
        endpoint.autoTestStatus = 'clean';
        endpoint.findings = 'No issues';
      }
    } catch (e) {
      endpoint.autoTestStatus = 'error';
      endpoint.findings = e.message;
      addLog(`Error testing ${endpoint.url}: ${e.message}`, 'error');
    }

    await sleep(300);
  }

  updateStats();
  updateNavBadges();
  addLog(`━━━ Auto-Test complete. Check module tabs for detailed results. ━━━`, 'success');
}

function getSelectedPorts() {
  return SCAN_PORTS.filter((_, i) => {
    const cb = document.getElementById(`scanPort${i}`);
    return cb && cb.checked;
  }).map(p => p.port);
}

// ── Balance & Account Enrichment ──
async function enrichEndpoints() {
  if (SCAN_STATE.enriching) return;
  const ethEndpoints = SCAN_STATE.discovered.filter(r => r.protocol === 'Ethereum' && !r._enriched);
  if (ethEndpoints.length === 0) {
    addLog('No un-enriched Ethereum endpoints to check.', 'warning');
    return;
  }
  SCAN_STATE.enriching = true;
  addLog(`━━━ Enriching ${ethEndpoints.length} Ethereum endpoints (accounts & balances)... ━━━`, 'info');
  const enrichBtn = document.getElementById('enrichBtn');
  if (enrichBtn) { enrichBtn.disabled = true; enrichBtn.innerHTML = '<span class="spinner"></span> Checking...'; }

  for (let i = 0; i < ethEndpoints.length; i++) {
    const ep = ethEndpoints[i];
    ep._enriched = true;
    ep.accounts = [];
    ep.totalBalance = '0';
    try {
      const client = new RPCClient(ep.url, 5000);
      // Get accounts
      const accRes = await client.jsonRpc('eth_accounts');
      if (accRes.success && accRes.data && accRes.data.result && Array.isArray(accRes.data.result)) {
        ep.accounts = accRes.data.result;
        addLog(`${ep.ip}:${ep.port} — ${ep.accounts.length} account(s) found`, ep.accounts.length > 0 ? 'success' : 'info');

        // Check balances for each account
        let totalWei = BigInt(0);
        for (const addr of ep.accounts.slice(0, 10)) { // Max 10 accounts
          try {
            const balRes = await client.jsonRpc('eth_getBalance', [addr, 'latest']);
            if (balRes.success && balRes.data && balRes.data.result) {
              const wei = BigInt(balRes.data.result);
              totalWei += wei;
              if (wei > 0n) {
                const ethVal = Number(wei) / 1e18;
                addLog(`  💰 ${addr.slice(0, 10)}... = ${ethVal.toFixed(4)} ETH`, 'success');
              }
            }
          } catch (e) { }
          await sleep(100);
        }
        ep.totalBalance = totalWei.toString();
        ep.totalBalanceEth = (Number(totalWei) / 1e18).toFixed(4);
      }
    } catch (e) {
      addLog(`Error enriching ${ep.ip}: ${e.message}`, 'error');
    }
    // Live update table
    const tbody = document.getElementById('scanResultsBody');
    if (tbody) renderScanResults(tbody);
    await sleep(200);
  }

  SCAN_STATE.enriching = false;
  if (enrichBtn) { enrichBtn.disabled = false; enrichBtn.innerHTML = '💰 Check Balances'; }
  const withBal = SCAN_STATE.discovered.filter(r => r.totalBalance && r.totalBalance !== '0').length;
  const withAcc = SCAN_STATE.discovered.filter(r => r.accounts && r.accounts.length > 0).length;
  addLog(`━━━ Enrichment complete: ${withAcc} with accounts, ${withBal} with non-zero balance ━━━`, withBal > 0 ? 'success' : 'info');
}

function setFilter(key, value) {
  SCAN_STATE.filters[key] = value;
  const tbody = document.getElementById('scanResultsBody');
  if (tbody) renderScanResults(tbody);
  // Update filter chip highlights
  document.querySelectorAll('.filter-chip').forEach(el => {
    if (el.dataset.filterKey === key) {
      if (typeof value === 'boolean') {
        el.classList.toggle('active', value);
      } else {
        el.classList.toggle('active', el.dataset.filterValue === value);
      }
    }
  });
  // Update result count
  const countEl = document.getElementById('filteredCount');
  if (countEl) {
    const filtered = getFilteredResults();
    countEl.textContent = filtered.length === SCAN_STATE.discovered.length
      ? `${filtered.length} endpoints`
      : `${filtered.length} of ${SCAN_STATE.discovered.length} endpoints`;
  }
}

function toggleFilter(key) {
  SCAN_STATE.filters[key] = !SCAN_STATE.filters[key];
  setFilter(key, SCAN_STATE.filters[key]);
}

function getFilteredResults() {
  return SCAN_STATE.discovered.filter(r => {
    const f = SCAN_STATE.filters;
    if (f.protocol !== 'all' && r.protocol.toLowerCase() !== f.protocol) return false;
    if (f.hasBalance && (!r.totalBalance || r.totalBalance === '0')) return false;
    if (f.hasAccounts && (!r.accounts || r.accounts.length === 0)) return false;
    if (f.vulnerableOnly && r.autoTestStatus !== 'vulnerable') return false;
    return true;
  });
}

function stopScan() {
  SCAN_STATE.isScanning = false;
  addLog('Scanner stopped by user.', 'warning');
  updateScanUI();
}

function updateScanProgress() {
  const bar = document.getElementById('scanProgressBar');
  const txt = document.getElementById('scanProgressText');
  if (!bar || !txt) return;
  const pct = SCAN_STATE.total > 0 ? Math.round((SCAN_STATE.scanned / SCAN_STATE.total) * 100) : 0;
  bar.style.width = pct + '%';
  txt.textContent = `${SCAN_STATE.scanned}/${SCAN_STATE.total} probed — ${SCAN_STATE.discovered.length} found (${pct}%)`;
  const tbody = document.getElementById('scanResultsBody');
  if (tbody) renderScanResults(tbody);
}

function updateScanUI() {
  ['scanStartBtn', 'shodanSearchBtn'].forEach(id => {
    const btn = document.getElementById(id);
    if (btn) {
      btn.disabled = SCAN_STATE.isScanning;
      if (id === 'scanStartBtn') btn.innerHTML = SCAN_STATE.isScanning ? '<span class="spinner"></span> Scanning...' : '🛰️ Start Scan';
      else btn.innerHTML = SCAN_STATE.isScanning ? '<span class="spinner"></span> Searching...' : '🔍 Search & Scan';
    }
  });
  const stopBtn = document.getElementById('scanStopBtn');
  if (stopBtn) stopBtn.style.display = SCAN_STATE.isScanning ? 'inline-flex' : 'none';
  const stopBtn2 = document.getElementById('scanStopBtn2');
  if (stopBtn2) stopBtn2.style.display = SCAN_STATE.isScanning ? 'inline-flex' : 'none';
  updateScanProgress();
}

function renderScanResults(tbody) {
  if (!tbody) return;
  const filtered = getFilteredResults();
  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;color:var(--text-muted);padding:24px">No results match the selected filters</td></tr>`;
    return;
  }
  tbody.innerHTML = filtered.map((r, i) => {
    const accCount = r.accounts ? r.accounts.length : '—';
    const balDisplay = r._enriched
      ? (r.totalBalance && r.totalBalance !== '0'
        ? `<span style="color:var(--accent-green);font-weight:600">${r.totalBalanceEth} ETH</span>`
        : `<span style="color:var(--text-muted)">0</span>`)
      : `<span style="color:var(--text-muted)">—</span>`;
    return `
    <tr class="fade-in" style="animation-delay:${i * 20}ms">
      <td><span class="method-name">${escapeHtml(r.ip)}</span></td>
      <td><span class="method-name">${r.port}</span></td>
      <td><span class="severity severity-info">${r.protocol}</span></td>
      <td style="color:var(--text-secondary);font-size:0.8rem;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(r.client)}</td>
      <td>${accCount !== '—' ? `<span class="method-name" style="${r.accounts?.length > 0 ? 'color:var(--accent-green)' : ''}">${accCount}</span>` : `<span style="color:var(--text-muted)">—</span>`}</td>
      <td>${balDisplay}</td>
      <td style="color:var(--text-muted)">${r.latency}ms</td>
      <td>${r.autoTestStatus
        ? `<span class="severity ${r.autoTestStatus === 'vulnerable' ? 'severity-critical' : r.autoTestStatus === 'findings' ? 'severity-medium' : 'severity-minor'}">${escapeHtml(r.findings)}</span>`
        : `<button class="btn btn-primary btn-sm" onclick="sendToTester('${r.url}','${r.protocol.toLowerCase()}')" style="padding:4px 12px;font-size:0.7rem">Test →</button>`
      }</td>
    </tr>`;
  }).join('');
}

function sendToTester(url, protocol) {
  document.getElementById('targetUrl').value = url;
  setInputMode('url');
  document.getElementById('protocolSelect').value = protocol === 'tendermint' ? 'tendermint' : protocol === 'solana' ? 'solana' : 'ethereum';
  switchModule('discovery');
  addLog(`Target set to ${url} (${protocol}) — ready for full testing`, 'success');
}

function setScannerTab(tab) {
  SCAN_STATE.scannerTab = tab;
  renderScannerContent();
}

function useShodanQuery(query) {
  const input = document.getElementById('shodanQueryInput');
  if (input) input.value = query;
}

// ── Scanner Custom UI Rendering ──
function renderScannerContent() {
  const panel = document.getElementById('contentBody');
  const title = document.getElementById('contentTitle');
  title.innerHTML = '<span class="module-icon">🛰️</span> RPC Endpoint Scanner';

  const tab = SCAN_STATE.scannerTab;

  let html = `<div class="module-desc">
    Built-in endpoint discovery scanner. Use <strong>Manual IPs</strong> to scan IP ranges directly, or
    <strong>Shodan Query</strong> to search the Shodan database and auto-scan results. Discovered endpoints can be
    automatically vulnerability-tested with the Auto-Test toggle.
  </div>`;

  // Tab switcher
  html += `<div class="input-mode-toggle" style="margin-bottom:20px">
    <button class="mode-btn ${tab === 'manual' ? 'active' : ''}" onclick="setScannerTab('manual')">📋 Manual IPs</button>
    <button class="mode-btn ${tab === 'shodan' ? 'active' : ''}" onclick="setScannerTab('shodan')">🔍 Shodan Query</button>
  </div>`;

  if (tab === 'manual') {
    html += renderManualScanTab();
  } else {
    html += renderShodanQueryTab();
  }

  // Progress
  html += `<div class="test-progress" style="margin-top:20px">
    <div class="progress-bar-container"><div class="progress-bar" id="scanProgressBar" style="width:0%"></div></div>
    <div class="progress-text" id="scanProgressText">Ready</div>
  </div>`;

  // Results
  if (SCAN_STATE.discovered.length > 0) {
    const f = SCAN_STATE.filters;
    html += `<div class="results-container" style="margin-top:20px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <span style="font-size:0.85rem;font-weight:600;color:var(--text-accent)">🎯 <span id="filteredCount">${SCAN_STATE.discovered.length} endpoints</span></span>
        <div style="display:flex;gap:8px">
          <button class="btn btn-success btn-sm" id="enrichBtn" onclick="enrichEndpoints()" style="padding:4px 14px;font-size:0.72rem">💰 Check Balances</button>
          <button class="btn btn-secondary btn-sm" onclick="exportScanResults()" style="padding:4px 14px;font-size:0.72rem">📋 Export</button>
        </div>
      </div>
      <div class="filter-bar">
        <span class="filter-label">Filter:</span>
        <button class="filter-chip ${f.protocol === 'all' ? 'active' : ''}" data-filter-key="protocol" data-filter-value="all" onclick="setFilter('protocol','all')">All</button>
        <button class="filter-chip ${f.protocol === 'ethereum' ? 'active' : ''}" data-filter-key="protocol" data-filter-value="ethereum" onclick="setFilter('protocol','ethereum')">🔷 ETH</button>
        <button class="filter-chip ${f.protocol === 'tendermint' ? 'active' : ''}" data-filter-key="protocol" data-filter-value="tendermint" onclick="setFilter('protocol','tendermint')">⛓️ Tendermint</button>
        <button class="filter-chip ${f.protocol === 'solana' ? 'active' : ''}" data-filter-key="protocol" data-filter-value="solana" onclick="setFilter('protocol','solana')">☀️ Solana</button>
        <span style="width:1px;height:20px;background:var(--border-subtle);margin:0 4px"></span>
        <button class="filter-chip ${f.hasAccounts ? 'active' : ''}" data-filter-key="hasAccounts" onclick="toggleFilter('hasAccounts')">👤 Has Accounts</button>
        <button class="filter-chip ${f.hasBalance ? 'active' : ''}" data-filter-key="hasBalance" onclick="toggleFilter('hasBalance')">💰 Has Balance</button>
        <button class="filter-chip ${f.vulnerableOnly ? 'active' : ''}" data-filter-key="vulnerableOnly" onclick="toggleFilter('vulnerableOnly')">⚠️ Vulnerable</button>
      </div>
      <table class="results-table">
        <thead><tr>
          <th>IP</th><th>Port</th><th>Protocol</th><th>Client</th><th>Accounts</th><th>Balance</th><th>Latency</th><th>Action</th>
        </tr></thead>
        <tbody id="scanResultsBody"></tbody>
      </table>
    </div>`;
  } else if (SCAN_STATE.scanned > 0 && !SCAN_STATE.isScanning) {
    html += `<div class="empty-state" style="margin-top:20px">
      <div class="empty-icon">🔇</div>
      <h3>No endpoints found</h3>
      <p>None of the probed targets had active blockchain RPC services. Try a different IP range or query.</p>
    </div>`;
  }

  panel.innerHTML = html;

  const tbody = document.getElementById('scanResultsBody');
  if (tbody) renderScanResults(tbody);

  // Restore API key from localStorage
  const apiInput = document.getElementById('shodanApiKeyInput');
  if (apiInput && !apiInput.value) apiInput.value = getShodanApiKey();

  // IP count live update
  const ipInput = document.getElementById('scanIpInput');
  if (ipInput) {
    ipInput.addEventListener('input', () => {
      const count = parseIPInput(ipInput.value).length;
      const el = document.getElementById('scanIpCount');
      if (el) el.textContent = count > 0 ? `${count} IPs parsed` : '';
    });
  }
}

function renderManualScanTab() {
  let html = `<div class="scanner-config">
    <div class="scanner-input-section">
      <label class="scanner-label">Target IPs <span style="color:var(--text-muted);font-weight:400">(one per line, CIDR, or range)</span></label>
      <textarea id="scanIpInput" class="scanner-textarea" rows="5" spellcheck="false"
        placeholder="Examples:&#10;103.243.21.48&#10;192.168.1.0/24&#10;10.0.0.1-50&#10;# Comments with # are ignored"></textarea>
    </div>

    <div class="scanner-options-row">
      <div class="scanner-ports">
        <label class="scanner-label">Ports</label>
        <div class="scanner-port-grid">`;

  SCAN_PORTS.forEach((p, i) => {
    html += `<label class="scanner-port-check">
      <input type="checkbox" id="scanPort${i}" ${p.checked ? 'checked' : ''}>
      <span>${p.port}</span>
      <span class="scanner-port-hint">${p.label}</span>
    </label>`;
  });

  html += `</div></div>
      <div class="scanner-settings">
        <label class="scanner-label">Concurrency</label>
        <div class="scanner-slider-row">
          <input type="range" id="scanConcurrency" min="1" max="20" value="10" class="scanner-slider"
            oninput="document.getElementById('concVal').textContent=this.value">
          <span id="concVal" class="scanner-val">10</span>
        </div>
        <label class="scanner-label" style="margin-top:10px">Timeout (sec)</label>
        <div class="scanner-slider-row">
          <input type="range" id="scanTimeout" min="2" max="15" value="5" class="scanner-slider"
            oninput="document.getElementById('toVal').textContent=this.value">
          <span id="toVal" class="scanner-val">5</span>
        </div>
      </div>
    </div>

    <div class="scanner-toggles" style="margin-top:14px;display:flex;gap:20px;flex-wrap:wrap">
      <label class="scanner-port-check" style="padding:8px 14px;border:1px solid var(--border-subtle);border-radius:6px">
        <input type="checkbox" id="useInternetDB" checked>
        <span style="font-size:0.78rem">🌐 InternetDB Pre-filter</span>
        <span class="scanner-port-hint" style="margin-left:8px">Free, skips dead IPs</span>
      </label>
      <label class="scanner-port-check" style="padding:8px 14px;border:1px solid var(--border-subtle);border-radius:6px">
        <input type="checkbox" id="autoTestToggle">
        <span style="font-size:0.78rem">⚡ Auto-Test Findings</span>
        <span class="scanner-port-hint" style="margin-left:8px">Run vuln scan on found endpoints</span>
      </label>
    </div>

    <div class="scanner-actions">
      <button class="btn btn-primary" id="scanStartBtn" onclick="runScan()">🛰️ Start Scan</button>
      <button class="btn btn-danger btn-sm" id="scanStopBtn" onclick="stopScan()" style="display:none">■ Stop</button>
      <span style="font-size:0.75rem;color:var(--text-muted);align-self:center" id="scanIpCount"></span>
    </div>
  </div>`;

  return html;
}

function renderShodanQueryTab() {
  const savedKey = getShodanApiKey();

  let html = `<div class="scanner-config">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
      <div>
        <label class="scanner-label">Shodan API Key <span style="color:var(--text-muted);font-weight:400">(free at <a href="https://account.shodan.io" target="_blank" style="color:var(--accent-cyan)">account.shodan.io</a>)</span></label>
        <input type="password" id="shodanApiKeyInput" class="scanner-textarea" style="height:auto;padding:12px 14px;font-size:0.82rem"
          placeholder="Enter your Shodan API key..." value="${escapeHtml(savedKey)}" spellcheck="false">
      </div>
      <div>
        <label class="scanner-label">Search Query</label>
        <input type="text" id="shodanQueryInput" class="scanner-textarea" style="height:auto;padding:12px 14px;font-size:0.82rem"
          placeholder='e.g. port:8545 jsonrpc' spellcheck="false">
      </div>
    </div>

    <div style="margin-top:14px">
      <label class="scanner-label">Example Queries <span style="color:var(--text-muted);font-weight:400">(click to use)</span></label>
      <div class="scanner-port-grid" style="grid-template-columns:repeat(auto-fill, minmax(240px, 1fr));gap:6px">`;

  SHODAN_EXAMPLE_QUERIES.forEach(q => {
    const icon = q.protocol === 'ethereum' ? '🔷' : q.protocol === 'tendermint' ? '⛓️' : '☀️';
    html += `<div class="shodan-query" onclick="useShodanQuery('${escapeHtml(q.query)}')" style="padding:8px 12px">
      <code style="font-size:0.72rem;color:var(--accent-purple)">${icon} ${escapeHtml(q.query)}</code>
      <span style="font-size:0.65rem;color:var(--text-muted)">${escapeHtml(q.desc)}</span>
    </div>`;
  });

  html += `</div></div>

    <div class="scanner-options-row" style="margin-top:14px">
      <div class="scanner-settings">
        <label class="scanner-label">Concurrency</label>
        <div class="scanner-slider-row">
          <input type="range" id="scanConcurrency2" min="1" max="20" value="10" class="scanner-slider"
            oninput="document.getElementById('concVal2').textContent=this.value">
          <span id="concVal2" class="scanner-val">10</span>
        </div>
      </div>
      <div class="scanner-settings">
        <label class="scanner-label">Timeout (sec)</label>
        <div class="scanner-slider-row">
          <input type="range" id="scanTimeout2" min="2" max="15" value="5" class="scanner-slider"
            oninput="document.getElementById('toVal2').textContent=this.value">
          <span id="toVal2" class="scanner-val">5</span>
        </div>
      </div>
    </div>

    <div class="scanner-toggles" style="margin-top:14px">
      <label class="scanner-port-check" style="padding:8px 14px;border:1px solid var(--border-subtle);border-radius:6px">
        <input type="checkbox" id="autoTestToggle2" checked>
        <span style="font-size:0.78rem">⚡ Auto-Test Findings</span>
        <span class="scanner-port-hint" style="margin-left:8px">Automatically run vulnerability scans on discovered endpoints</span>
      </label>
    </div>

    <div class="scanner-actions">
      <button class="btn btn-primary" id="shodanSearchBtn" onclick="runShodanQueryScan()">🔍 Search & Scan</button>
      <button class="btn btn-danger btn-sm" id="scanStopBtn2" onclick="stopScan()" style="display:none">■ Stop</button>
    </div>
  </div>`;

  return html;
}

function exportScanResults() {
  const text = SCAN_STATE.discovered.map(r => `${r.ip}:${r.port} # ${r.protocol} — ${r.client}`).join('\n');
  navigator.clipboard.writeText(text).then(() => {
    addLog(`Copied ${SCAN_STATE.discovered.length} endpoints to clipboard`, 'success');
  });
}

// ── Override renderModuleContent to handle scanner ──
const _originalRenderModule = renderModuleContent;
renderModuleContent = function () {
  if (APP_STATE.activeModule === 'scanner') {
    renderScannerContent();
    return;
  }
  _originalRenderModule();
};

// ── Init ──
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.module-nav-item').forEach(el => {
    el.addEventListener('click', () => switchModule(el.dataset.module));
  });

  switchModule('discovery');
  addLog('Tool initialized. Enter a target URL or IP/Port and select a protocol to begin.', 'info');
  addLog('Use the 🛰️ Scanner module to discover and auto-test RPC endpoints.', 'info');
});

