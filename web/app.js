'use strict';
const $ = (id) => document.getElementById(id);
let csrf = null;
let hosts = [];
let operations = [];
let audit = [];
function flash(text, bad = false) {
  const el = $('flash');
  el.hidden = !text; el.textContent = text; el.classList.toggle('is-error', bad);
  if (text) el.scrollIntoView({block: 'nearest', behavior: 'smooth'});
}
async function api(path, method = 'GET', data = null) {
  const headers = {};
  if (data !== null) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && csrf) headers['X-CSRF-Token'] = csrf;
  const response = await fetch(path, {
    method, headers, credentials: 'same-origin', cache: 'no-store',
    ...(data !== null ? {body: JSON.stringify(data)} : {}),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && path !== '/api/auth/login') showLogin();
    const detail = typeof payload.detail === 'string' ? payload.detail : JSON.stringify(payload.detail || payload);
    throw new Error(detail || `HTTP ${response.status}`);
  }
  return payload;
}
function showLogin() { csrf = null; $('app').hidden = true; $('auth-screen').hidden = false; }
function showApp() { $('auth-screen').hidden = true; $('app').hidden = false; }
function text(tag, value, className) {
  const el = document.createElement(tag); el.textContent = String(value ?? '');
  if (className) el.className = className;
  return el;
}
function cell(row, value) { row.appendChild(text('td', value)); }
function button(label, action, kind = 'secondary') {
  const el = document.createElement('button'); el.type = 'button'; el.className = kind;
  el.textContent = label; el.addEventListener('click', action); return el;
}
function hostLabel(id) { return hosts.find(h => h.id === id)?.name || `#${id}`; }
function fillHostSelect(id) {
  const select = $(id), oldValue = select.value;
  select.replaceChildren(new Option('Select a host', ''));
  for (const host of hosts) select.add(new Option(`${host.name} / ${host.address}`, String(host.id)));
  if (hosts.some(h => String(h.id) === oldValue)) select.value = oldValue;
  else if (hosts.length === 1) select.value = String(hosts[0].id);
}
async function reload() {
  const [a, b, c] = await Promise.all([api('/api/v1/hosts'), api('/api/v1/operations'), api('/api/v1/audit')]);
  hosts = a.items; operations = b.items; audit = c.items;
  $('host-count').textContent = hosts.length;
  $('pending-count').textContent = operations.filter(op => ['pending', 'staging', 'confirming', 'reverting', 'needs_review'].includes(op.status)).length;
  $('event-count').textContent = audit.length;
  fillHostSelect('firewall-host'); fillHostSelect('selinux-host');
  const hrows = $('host-rows'); hrows.replaceChildren();
  for (const h of hosts) {
    const tr = document.createElement('tr'); cell(tr, h.name); cell(tr, h.address);
    cell(tr, `${h.ssh_user}@${h.ssh_port}`);
    const td = document.createElement('td'); td.appendChild(button('Inspect', () => inspectHost(h.id)));
    tr.appendChild(td); hrows.appendChild(tr);
  }
  if (!hosts.length) hrows.appendChild(emptyRow('No real hosts enrolled yet.', 4));
  const orows = $('operation-rows'); orows.replaceChildren();
  for (const op of operations) {
    const tr = document.createElement('tr');
    cell(tr, `${op.kind} / ${op.id.slice(0, 9)}`); cell(tr, hostLabel(op.host_id));
    cell(tr, op.status); cell(tr, new Date(op.expires_at * 1000).toLocaleString());
    const td = document.createElement('td');
    if (op.status === 'pending') td.append(button('Confirm', () => operationAction(op.id, 'confirm'), 'primary'));
    if (['pending', 'needs_review', 'confirming', 'reverting'].includes(op.status)) {
      td.append(button('Revert / verify', () => operationAction(op.id, 'revert')));
    }
    tr.appendChild(td); orows.appendChild(tr);
  }
  if (!operations.length) orows.appendChild(emptyRow('No changes recorded.', 5));
  const ar = $('audit-rows'); ar.replaceChildren();
  for (const event of audit.slice(0, 50)) {
    const tr = document.createElement('tr');
    cell(tr, new Date(event.created_at * 1000).toLocaleString());
    cell(tr, event.action); cell(tr, event.host_id ?? '—'); cell(tr, event.detail);
    ar.appendChild(tr);
  }
  if (!audit.length) ar.appendChild(emptyRow('No audit events yet.', 4));
}
function emptyRow(message, colspan) {
  const tr = document.createElement('tr'); const td = text('td', message, 'muted');
  td.colSpan = colspan; tr.appendChild(td); return tr;
}
async function inspectHost(id) {
  try {
    flash('Inspecting actual Linux host over verified SSH...');
    const info = await api(`/api/v1/hosts/${id}/inspect`);
    $('host-inspection').textContent = JSON.stringify(info, null, 2);
    $('firewall-host').value = String(id); $('selinux-host').value = String(id);
    $('fw-zone').value = info.default_zone;
    flash(`Live discovery successful: ${info.os.name} / firewalld ${info.firewalld} / SELinux ${info.selinux}`);
  } catch (error) { flash(error.message, true); }
}
async function operationAction(id, action) {
  const op = operations.find(o => o.id === id);
  const label = op ? `${hostLabel(op.host_id)} / ${op.kind}` : id;
  if (!confirm(`Are you sure you want to ${action} ${label}?`)) return;
  try {
    const result = await api(`/api/v1/operations/${id}/${action}`, 'POST');
    flash(`${action}: ${result.status}${result.persistent === false ? ' (runtime only)' : ''}`);
    await reload();
  } catch (error) { flash(error.message, true); await reload(); }
}
function selectedHost(id) {
  const value = Number($(id).value);
  if (!value) throw new Error('Select a managed host first.');
  return value;
}
$('login-form').addEventListener('submit', async (event) => {
  event.preventDefault(); $('login-error').textContent = '';
  try {
    const credentials = {username: $('login-user').value, password: $('login-pass').value};
    const auth = await api('/api/auth/login', 'POST', credentials);
    csrf = auth.csrf; $('login-pass').value = ''; showApp(); await reload();
  } catch (error) { $('login-error').textContent = error.message; }
});
$('logout').addEventListener('click', async () => {
  try { await api('/api/auth/logout', 'POST'); } catch (_) { /* Always hide credentials locally. */ }
  showLogin();
});
$('refresh').addEventListener('click', () => reload().catch(e => flash(e.message, true)));
$('load-hosts').addEventListener('click', () => reload().catch(e => flash(e.message, true)));
$('host-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    flash('Checking host key, sudo privileges and real firewalld/SELinux state...');
    const data = {name: $('host-name').value, address: $('host-address').value,
                  ssh_user: $('host-user').value, ssh_port: Number($('host-port').value)};
    const out = await api('/api/v1/hosts', 'POST', data);
    $('host-form').reset(); $('host-port').value = '22';
    flash(`Enrolled real host #${out.id} — ${out.inspection.os.name}`); await reload();
  } catch (error) { flash(error.message, true); }
});
$('inspect-host').addEventListener('click', () => {
  try { inspectHost(selectedHost('firewall-host')); } catch (error) { flash(error.message, true); }
});
$('firewall-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const host = selectedHost('firewall-host');
    const data = {zone: $('fw-zone').value, port: Number($('fw-port').value),
                  protocol: $('fw-protocol').value, allow: $('fw-allow').value === 'true',
                  rollback_seconds: Number($('fw-timeout').value)};
    if (!confirm(`Stage ${data.allow ? 'ALLOW' : 'REMOVE'} ${data.port}/${data.protocol} on ${hostLabel(host)}?\nA remote rollback timer will be started before the runtime rule is changed.`)) return;
    const result = await api(`/api/v1/hosts/${host}/changes/firewall`, 'POST', data);
    flash(`Change staged: ${result.id}\n${result.confirmation_note}\nConfirm before ${new Date(result.expires_at * 1000).toLocaleString()} or it will roll back.`);
    await reload();
  } catch (error) { flash(error.message, true); await reload(); }
});
$('load-booleans').addEventListener('click', async () => {
  try {
    const id = selectedHost('selinux-host');
    const out = await api(`/api/v1/hosts/${id}/selinux/booleans`);
    const list = $('boolean-list'); list.replaceChildren();
    for (const item of out.items) list.appendChild(new Option(item.name + (item.enabled ? ' (on)' : ' (off)'), item.name));
    flash(`Loaded ${out.items.length} real SELinux booleans (runtime states).`);
  } catch (error) { flash(error.message, true); }
});
$('selinux-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const host = selectedHost('selinux-host');
    const data = {name: $('boolean-name').value, enabled: $('boolean-value').value === 'true',
                  rollback_seconds: Number($('boolean-timeout').value)};
    if (!confirm(`Change runtime SELinux boolean '${data.name}' on ${hostLabel(host)}?\nRequires an active host-side rollback timer.`)) return;
    const result = await api(`/api/v1/hosts/${host}/changes/selinux`, 'POST', data);
    flash(`Runtime SELinux change staged. Confirm before ${new Date(result.expires_at * 1000).toLocaleString()}. Confirmation is NOT persistent.`);
    await reload();
  } catch (error) { flash(error.message, true); await reload(); }
});
(async () => {
  try { const auth = await api('/api/auth/session'); csrf = auth.csrf; showApp(); await reload(); }
  catch (_) { showLogin(); }
})();
