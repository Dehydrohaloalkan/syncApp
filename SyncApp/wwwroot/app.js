const main = document.querySelector('#main');
const nav = document.querySelector('#projects');
let csrf = '';
let projects = [];
let selected = null;
let unlocked = '';

const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const short = value => String(value ?? '').slice(0, 12);

function notice(message, error = false) {
  const node = document.querySelector('#notice');
  node.textContent = message;
  node.className = error ? 'error' : '';
  node.style.display = 'block';
  clearTimeout(window.noticeTimer);
  window.noticeTimer = setTimeout(() => node.style.display = 'none', 6500);
}

async function request(path, method = 'GET', data = null) {
  const headers = {};
  if (method !== 'GET') headers['X-SyncApp-CSRF'] = csrf;
  if (data !== null) headers['Content-Type'] = 'application/json';
  const response = await fetch('/api' + path, {method, headers, body: data === null ? undefined : JSON.stringify(data)});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
  return result;
}

const get = path => request(path);
const post = (path, data) => request(path, 'POST', data);

async function refresh() {
  const result = await get('/session');
  csrf = result.csrf;
  projects = result.projects;
  nav.replaceChildren();
  for (const project of projects) {
    const button = document.createElement('button');
    button.textContent = `${project.folder} · ${project.side === 'Personal' ? 'личный' : 'рабочий'}`;
    button.classList.toggle('active', project.id === selected);
    button.addEventListener('click', () => selectProject(project.id));
    nav.append(button);
  }
  if (selected) showProject();
}

function field(id, name, label, type = 'text', required = true) {
  return `<div class="field"><label for="${id}">${label}</label><input id="${id}" name="${name}" type="${type}" ${required ? 'required' : ''} ${type === 'password' ? 'minlength="8" autocomplete="off"' : ''}></div>`;
}

function values(form) { return Object.fromEntries(new FormData(form).entries()); }
function bindForm(form, action) {
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try { await action(form); } catch (error) { notice(error.message, true); }
    finally { button.disabled = false; }
  });
}

document.querySelector('#new-project').addEventListener('click', () => {
  selected = null; unlocked = '';
  main.innerHTML = `<div class="eyebrow">Подключение</div><h1>Новый проект</h1><p class="lead">Подготовьте одинаковую чистую Git-копию на обоих компьютерах. Личная сторона публикует зашифрованные изменения, рабочая только читает junk.</p>
    <div class="grid"><section class="card"><h2>Личный компьютер</h2><form id="personal-form">
      ${field('personal-folder','folder','Имя папки в junk')}${field('personal-junk','junkPath','Путь к clone junk')}${field('personal-repo','repoPath','Корень подготовленной Git-репы')}${field('personal-secret','passphrase','Пароль локальных ключей','password')}
      <button class="primary" type="submit">Создать личный проект</button></form></section>
    <section class="card"><h2>Рабочий компьютер</h2><form id="work-form">
      ${field('work-folder','folder','Имя существующей папки в junk')}${field('work-junk','junkPath','Путь к clone junk')}${field('work-repo','repoPath','Корень рабочей Git-репы')}${field('work-fingerprint','peerFingerprint','Отпечаток личного устройства')}${field('work-secret','passphrase','Пароль локальных ключей','password')}
      <button class="primary" type="submit">Подключить ветку</button></form></section></div>`;
  bindForm(document.querySelector('#personal-form'), async form => {
    const result = await post('/projects/personal', values(form));
    selected = result.project.id;
    await refresh();
    notice('Локальная база закреплена. Синхронизируйте junk, чтобы опубликовать дескриптор, затем подключите рабочую копию.');
  });
  bindForm(document.querySelector('#work-form'), async form => {
    const result = await post('/projects/work', values(form));
    selected = result.project.id;
    await refresh();
    notice('Рабочая копия подключена. Передайте показанный публичный age-ключ на личную сторону.');
  });
});

function selectProject(id) { if (selected !== id) unlocked = ''; selected = id; showProject(); }
function password() {
  const input = document.querySelector('#project-password');
  unlocked = input?.value || unlocked;
  if (!unlocked) throw new Error('Введите пароль локальных ключей');
  return unlocked;
}

async function fingerprint(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

function showProject() {
  const project = projects.find(item => item.id === selected);
  if (!project) return;
  const personal = project.side === 'Personal';
  nav.querySelectorAll('button').forEach((button, index) => button.classList.toggle('active', projects[index].id === selected));
  const state = project.session
    ? `Применено пакетов: ${project.session.changeIds.length}. Создайте ручной коммит и подтвердите его.`
    : personal ? (project.workRecipient ? 'Рабочий ключ закреплён; опубликуйте зашифрованный baseline' : 'Ожидает подключения публичного ключа рабочей стороны')
      : project.baselineVerified ? 'Рабочий baseline совпал с личной копией' : 'Ожидает проверки baseline из junk';
  main.innerHTML = `<div class="eyebrow">${personal ? 'Личный компьютер' : 'Рабочий компьютер'}</div>
    <h1>${escapeHtml(project.folder)}</h1><p class="lead mono">${escapeHtml(project.repoPath)} · ${escapeHtml(project.branch || 'ветка ожидает код')}</p>
    <p class="status">${escapeHtml(state)}</p><div class="grid" style="margin-top:20px">
    <section class="card"><h2>Публичный ключ</h2><p>${personal ? 'Отпечаток личного устройства для проверки при подключении рабочей стороны:' : 'Скопируйте этот age-ключ и отпечаток на личный компьютер:'}</p><div id="fingerprint" class="fingerprint mono">Вычисляется…</div>
      ${personal ? '' : `<pre id="work-recipient" class="mono key-text">${escapeHtml(project.workRecipient)}</pre>`}
      <p class="hint">В junk передаются только подписанные зашифрованные данные и публичный дескриптор.</p>
      ${field('project-password','passphrase','Пароль локальных ключей','password')}<button id="lock">Заблокировать</button></section>
    <section class="card"><h2>GitHub / junk</h2><p>${personal ? 'Выполняется fast-forward pull, создаются только подписанные зашифрованные файлы. Отправка включается отдельно.' : 'Рабочая сторона выполняет только fast-forward pull и проверяет подпись и baseline.'}</p>
      ${personal ? '<div class="field"><label for="sync-count">Максимум пакетов в очереди (0 — все)</label><input id="sync-count" type="number" min="0" value="0"></div>' : ''}
      ${personal ? '<label class="check"><input id="sync-push" type="checkbox"> Отправить транспортный коммит в GitHub</label>' : ''}
      <button id="sync" class="primary">Синхронизировать junk</button><div id="sync-result"></div></section>
    ${personal ? `<section class="card"><h2>Подключить рабочий ключ</h2><p>Вставьте публичный recipient и сверьте его отпечаток. Личная сторона зашифрует digest подготовленной базы для рабочей стороны.</p>
      <form id="attach-work-key">${field('work-recipient-input','recipient','Публичный age recipient')}${field('work-key-fingerprint','fingerprint','Отпечаток recipient')}<button type="submit">Закрепить ключ</button></form></section>` : `<section class="card"><h2>Входящие изменения</h2><p>Пакеты загружаются только из личного направления. После применения создайте ручной коммит.</p>
      <button id="load-inbox">Проверить входящие</button><div id="inbox" class="list"></div></section>
      <section class="card"><h2>Завершение</h2><p>После проверки изменений создайте коммит в рабочей ветке, затем подтвердите его здесь. Это сохранит только локальный курсор.</p>
      <div class="actions"><button id="confirm">Коммит создан</button><button id="recover">Восстановить операцию</button></div></section>`}</div>`;
  document.querySelector('#project-password').value = unlocked;
  document.querySelector('#lock').onclick = () => { unlocked = ''; document.querySelector('#project-password').value = ''; notice('Ключи заблокированы'); };
  const identity = personal ? project.personalSigningKey + '\0' + project.personalRecipient : project.workRecipient;
  fingerprint(identity).then(value => {
    const node = document.querySelector('#fingerprint');
    if (node && selected === project.id) node.textContent = value;
  });
  bindProject(project);
}

function buttonAction(selector, action, rerender = false) {
  const button = document.querySelector(selector);
  if (!button) return;
  button.addEventListener('click', async () => {
    button.disabled = true;
    try { await action(); if (rerender) await refresh(); }
    catch (error) { notice(error.message, true); }
    finally { button.disabled = false; }
  });
}

async function loadInbox(project) {
  const changes = await post(`/projects/${project.id}/inbox`, {passphrase: password()});
  const node = document.querySelector('#inbox');
  const applied = new Set([...project.applied, ...(project.session?.changeIds || [])]);
  const previous = project.session?.changeIds.at(-1) || project.lastPersonalChangeId;
  const ordered = changes.sort((a, b) => (a.previousChangeId === previous ? -1 : b.previousChangeId === previous ? 1 : a.sourceCommit.localeCompare(b.sourceCommit)));
  node.innerHTML = ordered.length ? ordered.map(change => {
    const canApply = !applied.has(change.changeId) && change.previousChangeId === previous;
    return `<div class="list-item"><div><strong>${escapeHtml(change.message.split('\n')[0])}</strong><small class="mono">${escapeHtml(short(change.sourceCommit))} · ${escapeHtml(short(change.changeId))}</small></div><button data-apply="${escapeHtml(change.changeId)}" ${canApply ? '' : 'disabled'}>${applied.has(change.changeId) ? 'Применён' : 'Применить'}</button></div>`;
  }).join('') : '<p>Новых пакетов нет.</p>';
  node.querySelectorAll('[data-apply]:not([disabled])').forEach(button => button.onclick = async () => {
    button.disabled = true;
    try {
      const session = await post(`/projects/${project.id}/apply`, {changeId: button.dataset.apply, passphrase: password()});
      notice(`Применено пакетов: ${session.changeIds.length}. Создайте ручной коммит и подтвердите его.`);
      await refresh();
    } catch (error) { notice(error.message, true); button.disabled = false; }
  });
}

function bindProject(project) {
  const id = project.id;
  const personal = project.side === 'Personal';
  buttonAction('#sync', async () => {
    const maxCommits = personal ? Number(document.querySelector('#sync-count').value) : 0;
    const push = personal && document.querySelector('#sync-push').checked;
    const result = await post(`/projects/${id}/sync`, {passphrase: password(), push, maxCommits});
    await refresh();
    document.querySelector('#sync-result').textContent = personal
      ? `Подготовлено пакетов: ${result.preparedChanges}; файлов в коммите: ${result.committedFiles}; отправлено: ${result.pushed ? 'да' : 'нет'}.`
      : `Загружено зашифрованных пакетов: ${result.pulledPackages}; baseline: ${projects.find(x => x.id === selected)?.baselineVerified ? 'проверен' : 'ожидает'}.`;
    notice(result.pushed ? 'Зашифрованная синхронизация отправлена.' : personal ? 'Локальный транспортный коммит подготовлен. Отправьте его позже отдельным действием.' : 'Junk обновлён. Рабочая сторона ничего не отправляла.');
  });
  buttonAction('#load-inbox', () => loadInbox(project));
  buttonAction('#confirm', async () => {
    const result = await post(`/projects/${id}/confirm`, {passphrase: password()});
    notice(`Подтверждён ручной коммит ${short(result.targetCommit)}. Состояние сохранено локально.`);
  }, true);
  buttonAction('#recover', async () => {
    const result = await post(`/projects/${id}/recover`, {passphrase: password()});
    notice(result.session?.pendingChangeId ? 'Операция требует проверки' : 'Состояние восстановлено');
  }, true);
  const attachForm = document.querySelector('#attach-work-key');
  if (attachForm) bindForm(attachForm, async current => {
    const formData = values(current);
    await post(`/projects/${id}/attach-work-key`, formData);
    notice('Рабочий ключ закреплён. Опубликуйте подписанный зашифрованный baseline.');
    await refresh();
  });
}

refresh().catch(error => notice(error.message, true));
