// MSFile NAS V1 运维台前端。
// 只调用只读 API（/api/status、/api/files、/api/scans）和 POST /api/scans；
// 管理 token 通过 Authorization: Bearer 头传递，绝不放入 URL 或 localStorage。
"use strict";

var uiState = {
  offset: 0,
  limit: 50,
  total: 0
};

function $(id) { return document.getElementById(id); }

function apiToken() {
  // token 由部署方通过页面提示输入；保存在内存中，刷新后需重新输入。
  return window.__adminToken || "";
}

function request(method, url, body) {
  var headers = { "Accept": "application/json" };
  if (apiToken()) headers["Authorization"] = "Bearer " + apiToken();
  if (body) headers["Content-Type"] = "application/json";
  return fetch(url, { method: method, headers: headers, body: body ? JSON.stringify(body) : undefined })
    .then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) {
          var message = data && data.error_message_zh ? data.error_message_zh : ("HTTP " + res.status);
          throw new Error(message);
        }
        return data;
      });
    });
}

function showError(message) {
  var existing = document.querySelector(".error-banner");
  if (existing) existing.remove();
  var banner = document.createElement("div");
  banner.className = "error-banner";
  banner.textContent = "请求失败：" + message + "。若管理台配置了 admin_token，请先在控制台执行 window.__adminToken=\"你的令牌\" 后重试。";
  document.body.prepend(banner);
}

function fmtBytes(n) {
  if (n === null || n === undefined) return "-";
  return Number(n).toLocaleString("zh-CN");
}

function fmtTime(value) {
  if (!value) return "-";
  var d = new Date(value);
  if (isNaN(d.getTime())) return String(value);
  return d.toLocaleString("zh-CN", { hour12: false });
}

function stateClass(s) { return "state-" + String(s || "").toLowerCase(); }

function renderStatus(data) {
  $("st-service").textContent = data.service_status_zh || data.service_status;
  var modeText = data.access_mode === "public" ? "公共 public" : (data.access_mode === "private" ? "私有 private" : "-");
  if (data.access_mode === "private") modeText += "（白名单 " + data.whitelist_size + " 条）";
  $("st-mode").textContent = modeText;
  var counts = data.counts || {};
  $("st-total").textContent = fmtBytes(counts.total_contents);
  $("st-ready").textContent = fmtBytes(counts.ready_contents);
  $("st-invalid").textContent = fmtBytes(counts.invalid_contents);
  $("st-busy").textContent = fmtBytes(counts.indexing_count) + " / " + fmtBytes(counts.error_count);
  $("st-locations").textContent = fmtBytes(counts.valid_locations) + " / " + fmtBytes(counts.invalid_locations);
  $("st-queue").textContent = fmtBytes(data.queue_depth);
  var scanState = data.scan_running ? "全量扫描进行中…" : "";
  $("scan-state").textContent = scanState;
}

function retentionText(ms) {
  if (ms === null || ms === undefined) return "-";
  if (ms <= 0) return "即将回收";
  var hours = Math.floor(ms / 3600000);
  var minutes = Math.floor((ms % 3600000) / 60000);
  if (hours > 0) return hours + " 小时 " + minutes + " 分";
  return Math.max(1, Math.floor(ms / 1000)) + " 秒";
}

function renderFiles(data) {
  uiState.total = data.total || 0;
  var tbody = $("file-table").querySelector("tbody");
  tbody.textContent = "";
  (data.items || []).forEach(function (item) {
    var tr = document.createElement("tr");

    var tdHash = document.createElement("td");
    tdHash.className = "hash-cell";
    var link = document.createElement("button");
    link.type = "button";
    link.className = "hash-link";
    link.textContent = item.seed_hash;
    link.title = "查看该 Hash 的位置明细";
    link.addEventListener("click", function () { openDetail(item.seed_hash); });
    tdHash.appendChild(link);
    tr.appendChild(tdHash);

    function cell(value, mono) {
      var td = document.createElement("td");
      if (mono) td.className = "hash-cell";
      td.textContent = value;
      tr.appendChild(td);
    }

    cell(item.recommended_filename || "-", false);
    cell(item.media_type || "-", false);
    cell(fmtBytes(item.size_bytes), false);
    cell(String(item.valid_replicas), false);

    var tdState = document.createElement("td");
    var span = document.createElement("span");
    span.className = stateClass(item.state);
    span.textContent = zhState(item.state);
    tdState.appendChild(span);
    tr.appendChild(tdState);

    cell(fmtTime(item.created_at), true);
    cell(fmtTime(item.updated_at), true);
    cell(item.valid_replicas > 0 ? "-" : retentionText(item.retention_left_ms), false);

    tbody.appendChild(tr);
  });
  var page = Math.floor(uiState.offset / uiState.limit) + 1;
  var pages = Math.max(1, Math.ceil(uiState.total / uiState.limit));
  $("page-info").textContent = "第 " + page + " / " + pages + " 页，共 " + uiState.total + " 条";
}

function zhState(s) {
  switch (s) {
    case "ready": return "可提供";
    case "invalid": return "已失效";
    case "indexing": return "索引中";
    case "error": return "错误";
    default: return s || "-";
  }
}

function zhScanStatus(s) {
  switch (s) {
    case "running": return "进行中";
    case "succeeded": return "成功";
    case "partial": return "部分失败";
    case "failed": return "失败";
    default: return s || "-";
  }
}

function loadScans() {
  request("GET", "/api/scans").then(function (data) {
    var tbody = $("scan-table").querySelector("tbody");
    tbody.textContent = "";
    (data.items || []).forEach(function (run) {
      var tr = document.createElement("tr");
      [String(run.generation), fmtTime(run.started_at), fmtTime(run.finished_at), "", run.error_zh || "-"].forEach(function (value, index) {
        var td = document.createElement("td");
        if (index === 3) {
          var span = document.createElement("span");
          span.className = stateClass(run.status);
          span.textContent = zhScanStatus(run.status);
          td.appendChild(span);
        } else {
          td.textContent = value;
        }
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
  }).catch(showError);
}

function loadFiles() {
  var q = $("q").value.trim();
  var st = $("state").value;
  var url = "/api/files?limit=" + uiState.limit + "&offset=" + uiState.offset;
  if (q) url += "&q=" + encodeURIComponent(q);
  if (st) url += "&state=" + encodeURIComponent(st);
  request("GET", url).then(renderFiles).catch(showError);
}

function loadAll() {
  request("GET", "/api/status").then(renderStatus).catch(showError);
  loadFiles();
  loadScans();
}

function openDetail(seedHash) {
  request("GET", "/api/files/" + encodeURIComponent(seedHash)).then(function (data) {
    $("detail-hash").textContent = seedHash;
    var tbody = $("location-table").querySelector("tbody");
    tbody.textContent = "";
    (data.locations || []).forEach(function (loc) {
      var tr = document.createElement("tr");
      [loc.relative_path, "", fmtBytes(loc.size_bytes), fmtTime(new Date(Number(loc.mtime_ns) / 1e6)), loc.invalid_since ? fmtTime(loc.invalid_since) : "-", loc.last_error_zh || "-"].forEach(function (value, index) {
        var td = document.createElement("td");
        if (index === 1) {
          var span = document.createElement("span");
          span.className = stateClass(loc.state);
          span.textContent = zhState(loc.state);
          td.appendChild(span);
        } else {
          td.textContent = value;
        }
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    $("detail-panel").hidden = false;
    $("detail-panel").scrollIntoView({ behavior: "smooth" });
  }).catch(showError);
}

$("btn-refresh").addEventListener("click", function () { uiState.offset = 0; loadAll(); });
$("btn-prev").addEventListener("click", function () {
  if (uiState.offset - uiState.limit >= 0) { uiState.offset -= uiState.limit; loadFiles(); }
});
$("btn-next").addEventListener("click", function () {
  if (uiState.offset + uiState.limit < uiState.total) { uiState.offset += uiState.limit; loadFiles(); }
});
$("btn-close-detail").addEventListener("click", function () { $("detail-panel").hidden = true; });

$("btn-scan").addEventListener("click", function () {
  $("btn-scan").disabled = true;
  $("scan-state").textContent = "正在触发…";
  request("POST", "/api/scans", {}).then(function () {
    $("scan-state").textContent = "已触发，等待扫描完成…";
    setTimeout(loadAll, 1500);
  }).catch(function (err) {
    $("scan-state").textContent = "";
    showError(err.message);
  }).finally(function () {
    setTimeout(function () { $("btn-scan").disabled = false; }, 3000);
  });
});

// 每 10 秒自动刷新状态与扫描进度；文件列表保持用户当前页不被打断。
setInterval(function () {
  request("GET", "/api/status").then(renderStatus).catch(function () {});
}, 10000);

loadAll();
