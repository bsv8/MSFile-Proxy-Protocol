// MSFile 公共内容索引前端。
// 公共页面只查询当前可用内容；详情页通过服务端提供的地址下载原文件。
"use strict";

var uiState = {
  offset: 0,
  limit: 50,
  total: 0
};

function $(id) { return document.getElementById(id); }

function request(method, url) {
  return fetch(url, {
    method: method,
    headers: { "Accept": "application/json" }
  }).then(function (res) {
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
  banner.setAttribute("role", "alert");
  banner.textContent = "请求失败：" + message;
  document.querySelector("main").prepend(banner);
}

function fmtBytes(value) {
  if (value === null || value === undefined || isNaN(Number(value))) return "-";
  var bytes = Number(value);
  if (bytes === 0) return "0 B";
  var units = ["B", "KB", "MB", "GB", "TB"];
  var index = Math.floor(Math.log(Math.abs(bytes)) / Math.log(1024));
  index = Math.max(0, Math.min(index, units.length - 1));
  var amount = bytes / Math.pow(1024, index);
  var digits = index === 0 ? 0 : (amount >= 10 ? 1 : 2);
  return amount.toFixed(digits) + " " + units[index];
}

function shortHash(hash) {
  hash = String(hash || "");
  if (hash.length <= 12) return hash || "-";
  return hash.slice(0, 6) + "..." + hash.slice(-6);
}

function appendCell(row, value, className) {
  var cell = document.createElement("td");
  if (className) cell.className = className;
  cell.textContent = value === null || value === undefined || value === "" ? "-" : String(value);
  row.appendChild(cell);
  return cell;
}

function appendStatusCell(row) {
  var cell = document.createElement("td");
  var state = document.createElement("span");
  state.className = "state-ready";
  state.textContent = "有效";
  cell.appendChild(state);
  row.appendChild(cell);
}

function appendDetailCell(row, seedHash) {
  var cell = document.createElement("td");
  var button = document.createElement("button");
  button.type = "button";
  button.className = "detail-button";
  button.textContent = "查看详情";
  button.addEventListener("click", function () { openDetail(seedHash); });
  cell.appendChild(button);
  row.appendChild(cell);
}

function renderFiles(data) {
  uiState.total = Number(data.total || 0);
  var tbody = $("file-table").querySelector("tbody");
  tbody.textContent = "";
  var items = data.items || [];

  if (items.length === 0) {
    var emptyRow = document.createElement("tr");
    var emptyCell = document.createElement("td");
    emptyCell.className = "empty-state";
    emptyCell.colSpan = 6;
    emptyCell.textContent = $("q").value.trim() ? "没有找到匹配的可用内容" : "暂无可用内容";
    emptyRow.appendChild(emptyCell);
    tbody.appendChild(emptyRow);
  }

  items.forEach(function (item) {
    var seedHash = String(item.seed_hash || "");
    var row = document.createElement("tr");
    row.className = "file-row";

    var hashCell = document.createElement("td");
    hashCell.className = "hash-cell";
    var hashButton = document.createElement("button");
    hashButton.type = "button";
    hashButton.className = "hash-link";
    hashButton.textContent = shortHash(seedHash);
    hashButton.title = "完整 Seed Hash：" + seedHash;
    hashButton.setAttribute("aria-label", "查看 " + shortHash(seedHash) + " 的详情");
    hashButton.addEventListener("click", function () { openDetail(seedHash); });
    hashCell.appendChild(hashButton);
    row.appendChild(hashCell);

    appendCell(row, item.recommended_filename, "filename-cell");
    appendCell(row, item.media_type, "type-cell");
    appendCell(row, fmtBytes(item.size_bytes), "size-cell");
    appendStatusCell(row);
    appendDetailCell(row, seedHash);
    tbody.appendChild(row);
  });

  var page = Math.floor(uiState.offset / uiState.limit) + 1;
  var pages = Math.max(1, Math.ceil(uiState.total / uiState.limit));
  $("page-info").textContent = "第 " + page + " / " + pages + " 页";
  $("result-count").textContent = "共 " + uiState.total.toLocaleString("zh-CN") + " 个可用文件";
  $("btn-prev").disabled = uiState.offset === 0;
  $("btn-next").disabled = uiState.offset + uiState.limit >= uiState.total;
}

function loadFiles() {
  var query = $("q").value.trim();
  var url = "/api/files?limit=" + uiState.limit + "&offset=" + uiState.offset;
  if (query) url += "&q=" + encodeURIComponent(query);
  request("GET", url).then(renderFiles).catch(showError);
}

function openDetail(seedHash) {
  request("GET", "/api/files/" + encodeURIComponent(seedHash)).then(function (data) {
    var content = data.content || {};
    var fullHash = content.seed_hash || seedHash;
    var filename = content.recommended_filename || "download";
    $("detail-filename").textContent = filename;
    $("detail-filename-meta").textContent = filename;
    $("detail-hash").textContent = shortHash(fullHash);
    $("detail-hash").title = "完整 Seed Hash：" + fullHash;
    $("detail-type").textContent = content.media_type || "application/octet-stream";
    $("detail-size").textContent = fmtBytes(content.size_bytes);
    $("detail-state").textContent = "有效，可下载";

    var download = $("btn-download");
    download.href = data.download_url || ("/api/files/" + encodeURIComponent(fullHash) + "/download");
    download.setAttribute("download", filename);
    $("detail-panel").hidden = false;
    $("detail-panel").scrollIntoView({ behavior: "smooth", block: "start" });
  }).catch(showError);
}

$("filters").addEventListener("submit", function (event) {
  event.preventDefault();
  uiState.offset = 0;
  loadFiles();
});

$("btn-refresh").addEventListener("click", function () {
  uiState.offset = 0;
  loadFiles();
});

$("btn-prev").addEventListener("click", function () {
  if (uiState.offset >= uiState.limit) {
    uiState.offset -= uiState.limit;
    loadFiles();
  }
});

$("btn-next").addEventListener("click", function () {
  if (uiState.offset + uiState.limit < uiState.total) {
    uiState.offset += uiState.limit;
    loadFiles();
  }
});

$("btn-close-detail").addEventListener("click", function () {
  $("detail-panel").hidden = true;
});

loadFiles();
