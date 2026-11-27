"use strict";
const $ = (s) => document.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const PAGE = 100;

const state = { file: null, vendors: [], preview: null, mappingDirty: false, data: null,
                filter: { chip: "all", scope: "", q: "" }, page: 0, byUid: new Map() };

// ------------------------------------------------------------------ 초기화
fetch("/api/vendors").then((r) => r.json()).then((j) => {
  state.vendors = j.vendors;
  $("#ver").textContent = "v" + j.version;
  const sel = $("#vendor");
  sel.innerHTML = '<option value="auto">자동 판별</option>' + j.vendors.map((v) =>
    `<option value="${esc(v.key)}">${esc(v.label)}${v.verified ? "" : " (형식 확인 필요)"}</option>`).join("");
  updateHint();
});

function updateHint() {
  const v = state.vendors.find((x) => x.key === $("#vendor").value);
  $("#vendor-hint").textContent = v ? "입력: " + v.formats
    : "파일 내용을 보고 벤더를 판별합니다. 엑셀/CSV 는 열 이름으로 자동 인식합니다.";
}
$("#vendor").addEventListener("change", () => { updateHint(); state.mappingDirty = false; if (state.file) loadPreview(); });

const drop = $("#drop");
$("#file").addEventListener("change", (e) => setFile(e.target.files[0]));
["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", (e) => { if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]); });

function setFile(f) {
  if (!f) return;
  state.file = f;
  state.mappingDirty = false;
  $("#file-name").textContent = f.name + "  (" + Math.ceil(f.size / 1024).toLocaleString() + " KB)";
  drop.classList.add("has-file");
  $("#run").disabled = false;
  showError("");
  loadPreview();
}

function showError(msg) {
  const el = $("#error");
  el.hidden = !msg;
  el.textContent = msg || "";
}

// ------------------------------------------------------------------ 열 매핑 (표 형식)
let previewSeq = 0;
async function loadPreview() {
  const my = ++previewSeq;          // 늦게 도착한 이전 요청 응답은 무시
  $("#mapping-box").hidden = true;
  state.preview = null;
  state.sheet = null;
  const fd = new FormData();
  fd.append("file", state.file);
  fd.append("vendor", $("#vendor").value);
  try {
    const r = await fetch("/api/preview", { method: "POST", body: fd });
    const j = await r.json();
    if (my !== previewSeq || !r.ok || j.kind !== "table") return;
    state.preview = j;
    const sheet = j.sheets.find((s) => s.mapping.src && s.mapping.dst) || j.sheets[0];
    renderMapping(sheet);
  } catch (e) { /* 미리보기 실패는 분석 단계에서 다시 안내 */ }
}

function renderMapping(sheet) {
  if (!sheet) return;
  state.sheet = sheet;
  const box = $("#mapping-box");
  box.hidden = false;
  const ok = sheet.mapping.src && sheet.mapping.dst;
  box.open = !ok;
  $("#mapping-sheet").textContent = `시트: ${sheet.sheet} / 헤더 ${sheet.header_row + 1}행` +
    (state.preview.sheets.length > 1 ? ` (시트 ${state.preview.sheets.length}개)` : "");
  const fields = state.preview.fields;   // [[key, label], ...] 순서 유지
  const opts = ['<option value="">(없음)</option>'].concat(sheet.header.map((h) => `<option>${esc(h)}</option>`)).join("");
  $("#mapping").innerHTML = fields.map(([k, label]) =>
    `<label class="${k === "src" || k === "dst" ? "req" : ""}"><span>${esc(label)}</span>
       <select data-field="${k}">${opts}</select></label>`).join("");
  $("#mapping").querySelectorAll("select").forEach((s) => {
    s.value = sheet.mapping[s.dataset.field] || "";
    s.addEventListener("change", () => { state.mappingDirty = true; });
  });
  $("#sample").innerHTML = "<tr>" + sheet.header.map((h) => `<th>${esc(h)}</th>`).join("") + "</tr>" +
    sheet.sample.map((row) => "<tr>" + row.map((c) => `<td title="${esc(c)}">${esc(c)}</td>`).join("") + "</tr>").join("");
}

function currentMapping() {
  const m = {};
  $("#mapping").querySelectorAll("select").forEach((s) => { if (s.value) m[s.dataset.field] = s.value; });
  return m;
}

// ------------------------------------------------------------------ 분석
$("#run").addEventListener("click", async () => {
  if (!state.file) return;
  const btn = $("#run");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>분석 중…';
  showError("");
  const fd = new FormData();
  fd.append("file", state.file);
  fd.append("vendor", $("#vendor").value);
  fd.append("options", JSON.stringify({
    include_disabled: $("#opt-disabled").checked, include_unused: $("#opt-unused").checked,
    detect_down: $("#opt-down").checked, detect_merge: $("#opt-merge").checked }));
  const popts = { infer_ip_from_name: $("#opt-nameip").checked, zero_as_24: $("#opt-zero24").checked };
  if (state.mappingDirty && state.sheet) {
    Object.assign(popts, { mapping: currentMapping(), header_row: state.sheet.header_row, sheet: state.sheet.sheet });
  }
  fd.append("parse_options", JSON.stringify(popts));
  try {
    const r = await fetch("/api/analyze", { method: "POST", body: fd });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error || "분석 실패");
    state.data = j;
    state.byUid = new Map(j.rules.map((x) => [x.uid, x]));
    state.filter = { chip: "all", scope: "", q: "" };
    $("#search").value = "";
    state.page = 0;
    renderResult();
  } catch (e) {
    showError(e.message);
    if (state.preview) $("#mapping-box").open = true;
  } finally {
    btn.disabled = false;
    btn.textContent = "분석";
  }
});

function renderResult() {
  const { summary: s, id } = state.data;
  $("#result").hidden = false;
  const took = s.elapsed < 0.1 ? "0.1초 미만" : `${s.elapsed.toFixed(1)}초`;
  $("#result-meta").textContent = `${state.data.vendor_label} · ${s.source} · 정책 그룹 ${s.scopes}개 · 분석 ${took}`;
  $("#dl-report").href = `/api/result/${id}/report.xlsx`;
  $("#dl-commands").href = `/api/result/${id}/commands.txt`;
  $("#dl-commands").textContent = s.commands_supported ? "정리 명령어 (CLI)" : "정리 대상 목록";
  $("#dl-cleaned").hidden = !state.data.has_cleaned;
  $("#dl-cleaned").href = `/api/result/${id}/cleaned.xlsx`;

  const st = s.by_status;
  const pct = s.total ? Math.round((s.removed / s.total) * 100) : 0;
  $("#stats").innerHTML = [
    ["", s.total, "전체 정책"], ["keep", s.remaining, "정리 후 정책"],
    ["remove", s.removed, `정리 대상 (${pct}%)`], ["remove", st.remove.count, "삭제 권고"],
    ["", st.candidate.count, "삭제 후보 (비활성·Hit 0)"], ["review", st.review.count, "검토 필요 (Any·충돌)"],
  ].map(([cls, n, label]) => `<div class="stat ${cls}"><b>${n.toLocaleString()}</b><span>${esc(label)}</span></div>`).join("");

  const un = $("#unverified");
  un.hidden = state.data.vendor_verified;
  un.textContent = "이 벤더의 export 형식은 실제 장비 샘플로 아직 검증하지 않았습니다. 위의 '열 매핑 확인'에서 열이 맞게 인식됐는지 확인해 주세요.";
  const w = $("#warnings");
  w.hidden = !s.warnings.length;
  w.innerHTML = s.warnings.map((x) => `<li>${esc(x)}</li>`).join("");

  const hot = $("#hotspots");
  hot.hidden = !s.hotspots.length;
  hot.innerHTML = s.hotspots.length ? `<p class="section-title">주요 근거 정책 — 이 정책 하나가 아래 정책들을 대량으로 가립니다. 실제로 활성 상태인지, 동작이 무엇인지 먼저 확인하세요.</p>` +
    s.hotspots.map((h) => `<button class="hot" data-goto="${h.uid}">
      <b>${h.count.toLocaleString()}개</b> 가림 · [${esc(h.scope)}] ${esc(h.rid)}${h.name ? " " + esc(h.name) : ""}
      <span class="muted">${esc(h.src)} → ${esc(h.dst)} / ${esc(h.svc)} · ${ACTION[h.action]}</span></button>`).join("") : "";

  const scopes = [...new Set(state.data.rules.map((r) => r.scope))];
  $("#scope-filter").innerHTML = '<option value="">전체 정책 그룹</option>' + scopes.map((x) => `<option>${esc(x)}</option>`).join("");
  $("#scope-filter").hidden = scopes.length < 2;

  const chips = [["all", "전체", s.total, ""], ["removed", "정리 대상", s.removed, "remove"]];
  for (const [code, v] of Object.entries(s.by_code)) if (v.count) chips.push([code, v.label, v.count, v.category]);
  $("#chips").innerHTML = chips.map(([k, label, n, cat]) =>
    `<button class="chip${state.filter.chip === k ? " active" : ""}" data-chip="${esc(k)}" data-cat="${cat}">${esc(label)}<b>${n}</b></button>`).join("");
  renderTable();
  $("#result").scrollIntoView({ behavior: "smooth", block: "start" });
}

$("#chips").addEventListener("click", (e) => {
  const b = e.target.closest(".chip");
  if (!b) return;
  state.filter.chip = b.dataset.chip;
  state.page = 0;
  $("#chips").querySelectorAll(".chip").forEach((c) => c.classList.toggle("active", c === b));
  renderTable();
});
$("#scope-filter").addEventListener("change", (e) => { state.filter.scope = e.target.value; state.page = 0; renderTable(); });
let qTimer;
$("#search").addEventListener("input", (e) => {
  clearTimeout(qTimer);
  qTimer = setTimeout(() => { state.filter.q = e.target.value.trim().toLowerCase(); state.page = 0; renderTable(); }, 150);
});

function filtered() {
  const { chip, scope, q } = state.filter;
  return state.data.rules.filter((r) => {
    if (scope && r.scope !== scope) return false;
    if (chip === "removed" && !r.removed) return false;
    if (chip !== "all" && chip !== "removed" && !r.findings.some((f) => f.code === chip)) return false;
    if (q) {
      const hay = [r.rid, r.name, r.src, r.dst, r.svc, r.src_zone, r.dst_zone, r.comment, r.resolved.src, r.resolved.dst].join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

const STATUS = { remove: "삭제 권고", candidate: "삭제 후보", review: "검토 필요", info: "참고", keep: "유지" };
const ACTION = { allow: "허용", deny: "차단", unknown: "동작 미확인" };
$("#hotspots").addEventListener("click", (e) => {
  const b = e.target.closest("[data-goto]");
  if (b) openDrawer(+b.dataset.goto);
});

function renderTable() {
  const rows = filtered();
  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  state.page = Math.min(state.page, pages - 1);
  const slice = rows.slice(state.page * PAGE, (state.page + 1) * PAGE);
  const multiScope = new Set(state.data.rules.map((r) => r.scope)).size > 1;
  const tbody = $("#rules tbody");
  if (!slice.length) {
    tbody.innerHTML = `<tr><td colspan="10" class="empty">조건에 맞는 정책이 없습니다.</td></tr>`;
  } else {
    tbody.innerHTML = slice.map((r) => `
      <tr data-uid="${r.uid}" class="${r.removed ? "removed" : ""}">
        <td><span class="badge ${r.status}">${STATUS[r.status]}</span></td>
        <td>${multiScope ? esc(r.scope) : '<span class="muted">-</span>'}</td>
        <td class="num">${r.seq}</td>
        <td class="rname">${esc(r.rid)}${r.enabled ? "" : '<span class="off">비활성</span>'}${r.name && r.name !== r.rid ? `<small>${esc(r.name)}</small>` : ""}</td>
        <td><span class="act ${r.action}">${ACTION[r.action]}</span></td>
        <td class="addr"><div class="clip" title="${esc(r.src)}">${esc(r.src)}</div></td>
        <td class="addr"><div class="clip" title="${esc(r.dst)}">${esc(r.dst)}</div></td>
        <td class="addr"><div class="clip" title="${esc(r.svc)}">${esc(r.svc)}</div></td>
        <td class="num">${r.hits == null ? "" : r.hits.toLocaleString()}</td>
        <td><div class="tags">${r.findings.map((f) => `<span class="tag ${f.category}">${esc(f.label)}</span>`).join("")}</div></td>
      </tr>`).join("");
  }
  const pager = $("#pager");
  if (pages <= 1) { pager.innerHTML = `<span class="muted small">${rows.length.toLocaleString()}건</span>`; return; }
  pager.innerHTML = `<button data-p="${state.page - 1}" ${state.page === 0 ? "disabled" : ""}>이전</button>
    <span class="muted small">${state.page + 1} / ${pages} 페이지 · ${rows.length.toLocaleString()}건</span>
    <button data-p="${state.page + 1}" ${state.page >= pages - 1 ? "disabled" : ""}>다음</button>`;
}
$("#pager").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-p]");
  if (!b) return;
  state.page = +b.dataset.p;
  renderTable();
  $("#rules").scrollIntoView({ block: "start" });
});
$("#rules tbody").addEventListener("click", (e) => {
  const tr = e.target.closest("tr[data-uid]");
  if (tr) openDrawer(+tr.dataset.uid);
});

// ------------------------------------------------------------------ 상세 패널
function ruleTitle(r) {
  const seq = String(r.seq) === String(r.rid) ? "" : `#${r.seq} `;
  return `${seq}${r.rid}${r.name && r.name !== r.rid ? " · " + r.name : ""}`;
}
function refLabel(uid) {
  const r = state.byUid.get(uid);
  return r ? ruleTitle(r) : uid;
}

function openDrawer(uid) {
  const r = state.byUid.get(uid);
  if (!r) return;
  $("#d-title").textContent = ruleTitle(r);
  const kv = [
    ["상태", `<span class="badge ${r.status}">${STATUS[r.status]}</span>${r.removed ? ' <span class="muted small">정리본에서 제외</span>' : ""}`],
    ["정책 그룹", esc(r.scope)], ["평가 순서", `${r.seq}번째`], ["동작", ACTION[r.action]], ["사용", r.enabled ? "활성" : "비활성"],
    ["출발지 존", esc(r.src_zone)], ["목적지 존", esc(r.dst_zone)],
    ["출발지", `${esc(r.src)}<br><code class="muted">${esc(r.resolved.src)}</code>`],
    ["목적지", `${esc(r.dst)}<br><code class="muted">${esc(r.resolved.dst)}</code>`],
    ["서비스", `${esc(r.svc)}<br><code class="muted">${esc(r.resolved.svc)}</code>`],
    ["애플리케이션", esc(r.app)], ["사용자", esc(r.users)],
    ["Hit", r.hits == null ? '<span class="muted">정보 없음</span>' : r.hits.toLocaleString()],
    ["설명", esc(r.comment) || '<span class="muted">-</span>'],
  ];
  const findings = r.findings.length ? r.findings.map((f) => `
    <div class="finding ${f.category}">
      <span class="badge ${f.category}">${esc(f.label)}</span>
      <p>${esc(f.desc)}</p>
      ${f.detail ? `<p class="muted">${esc(f.detail)}</p>` : ""}
      ${f.refs.length ? `<div class="refs">${f.refs.map((u) => `<button data-goto="${u}">${esc(refLabel(u))}</button>`).join("")}</div>` : ""}
    </div>`).join("") : '<p class="muted">특이사항 없음</p>';
  $("#d-body").innerHTML = `<div><p class="section-title">판정</p><div style="display:grid;gap:8px">${findings}</div></div>
    <div><p class="section-title">정책 내용 (아래 회색 글씨는 객체를 해석한 실제 값)</p>
    <dl class="kv">${kv.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl></div>`;
  $("#drawer").classList.add("open");
  $("#drawer").setAttribute("aria-hidden", "false");
  $("#scrim").hidden = false;
}
function closeDrawer() {
  $("#drawer").classList.remove("open");
  $("#drawer").setAttribute("aria-hidden", "true");
  $("#scrim").hidden = true;
}
$("#d-close").addEventListener("click", closeDrawer);
$("#scrim").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
$("#d-body").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-goto]");
  if (b) openDrawer(+b.dataset.goto);
});
