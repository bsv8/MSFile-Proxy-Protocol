// MSFile Web 前端。
// 仅在服务端明确开放 public 内容索引时查询文件；详情页通过服务端提供的地址下载原文件。
import {
  currentBrowserNetworkAddress,
  hasSameHostname,
  normalizeHostname,
  validateNetworkPayload
} from "./network-address.mjs";

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
        var error = new Error(message);
        error.status = res.status;
        error.code = data && data.error_code ? data.error_code : "";
        throw error;
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

function showNetworkError(message, keepContent) {
  var banner = $("network-error");
  banner.textContent = "网络接入地址错误：" + message;
  banner.hidden = false;
  $("network-state").textContent = "加载失败";
  if (!keepContent) $("network-content").hidden = true;
}

function clearNetworkError() {
  var banner = $("network-error");
  banner.textContent = "";
  banner.hidden = true;
}

function createCopyButton(targetID) {
  var button = document.createElement("button");
  button.type = "button";
  button.className = "copy-button";
  button.textContent = "复制";
  button.setAttribute("data-copy-target", targetID);
  bindCopyButton(button);
  return button;
}

function copyText(value) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(value);
  }
  var area = document.createElement("textarea");
  area.value = value;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  var copied = false;
  try { copied = document.execCommand("copy"); } catch (_) { copied = false; }
  area.remove();
  return copied ? Promise.resolve() : Promise.reject(new Error("浏览器拒绝了剪贴板操作"));
}

function bindCopyButton(button) {
  button.addEventListener("click", function () {
    var target = $(button.getAttribute("data-copy-target"));
    var value = target ? target.textContent.trim() : "";
    if (!value) {
      showNetworkError("没有可复制的地址", true);
      return;
    }
    copyText(value).then(function () {
      var original = button.textContent;
      button.textContent = "已复制";
      window.setTimeout(function () { button.textContent = original; }, 1600);
    }).catch(function (error) {
      showNetworkError(error.message || "复制失败", true);
    });
  });
}

function renderDirectAddress(item, index) {
  var card = document.createElement("article");
  card.className = "address-card generated-direct";

  var topline = document.createElement("div");
  topline.className = "address-card-topline";
  var title = document.createElement("div");
  var transport = document.createElement("p");
  transport.className = "address-transport";
  transport.textContent = "WebRTC Direct";
  var heading = document.createElement("h3");
  heading.textContent = "公网 UDP 直连 " + (index + 1);
  title.appendChild(transport);
  title.appendChild(heading);
  var badge = document.createElement("span");
  badge.className = "address-badge";
  badge.textContent = "UDP";
  topline.appendChild(title);
  topline.appendChild(badge);
  card.appendChild(topline);

  var valueRow = document.createElement("div");
  valueRow.className = "address-value-row";
  var value = document.createElement("code");
  value.className = "address-value";
  value.id = "direct-address-" + index;
  value.textContent = item.value;
  valueRow.appendChild(value);
  valueRow.appendChild(createCopyButton(value.id));
  card.appendChild(valueRow);

  var note = document.createElement("p");
  note.className = "address-note";
  note.textContent = "公网 UDP 直连，不经普通 Cloudflare HTTP 代理；hostname、端口、certhash 和 PeerId 均来自服务端运行时信息。";
  card.appendChild(note);
  return card;
}

function renderNetwork(data) {
  var network = validateNetworkPayload(data);
  clearNetworkError();
  $("content-hero").hidden = !network.contentIndexEnabled;
  $("content-index").hidden = !network.contentIndexEnabled;
  if (!network.contentIndexEnabled) $("detail-panel").hidden = true;
  if (network.contentIndexEnabled) loadFiles();
  $("network-peer-id").textContent = network.peerID;
  $("network-public-key").textContent = network.publicKey;

  var list = $("direct-address-list");
  list.querySelectorAll(".generated-direct").forEach(function (card) { card.remove(); });
  $("direct-empty").hidden = network.direct.length !== 0;
  network.direct.forEach(function (item, index) {
    list.insertBefore(renderDirectAddress(item, index), $("direct-empty"));
  });

  var wssError = null;
  var wss = $("wss-address");
  var wssRow = $("wss-address-row");
  try {
    wss.textContent = currentBrowserNetworkAddress(window.location, network.peerID);
    wssRow.hidden = false;
    $("wss-note").textContent = "经 Cloudflare TCP/TLS；地址使用当前浏览器页面的域名和端口生成。";
  } catch (error) {
    wss.textContent = "";
    wssRow.hidden = true;
    $("wss-note").textContent = error.message;
    wssError = error.message;
  }

  var sameHost = hasSameHostname(normalizeHostname(window.location.hostname), network.direct);
  $("same-host-note").hidden = !sameHost;
  $("network-content").hidden = false;
  if (wssError) {
    showNetworkError(wssError, true);
  } else {
    $("network-state").textContent = "已加载";
  }
}

function loadNetworkInfo(attempt) {
  var currentAttempt = attempt || 0;
  request("GET", "/api/network-info").then(renderNetwork).catch(function (error) {
    if (error.code === "network_info_not_ready" && currentAttempt < 5) {
      // listener 已可接收请求但运行时 certhash 尚未发布时，短暂退避重试。
      var delay = Math.min(2000, 200 * Math.pow(2, currentAttempt));
      $("network-state").textContent = "网络信息准备中…";
      window.setTimeout(function () { loadNetworkInfo(currentAttempt + 1); }, delay);
      return;
    }
    showNetworkError(error.message || "无法读取网络信息", false);
  });
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
    emptyCell.colSpan = 5;
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
    $("detail-hash").textContent = fullHash;
    $("detail-hash").title = "完整 Seed Hash：" + fullHash;

    var filenames = Array.isArray(data.filenames) ? data.filenames : [];
    // 兼容旧服务端：升级前的详情响应只有推荐文件名，仍保证页面有文件名可看。
    if (filenames.length === 0 && content.recommended_filename) {
      filenames = [content.recommended_filename];
    }
    var filenameList = $("detail-filenames");
    filenameList.textContent = "";
    if (filenames.length === 0) {
      var emptyFilename = document.createElement("li");
      emptyFilename.className = "detail-filenames-empty";
      emptyFilename.textContent = "暂无关联文件名";
      filenameList.appendChild(emptyFilename);
    } else {
      filenames.forEach(function (name) {
        var filenameItem = document.createElement("li");
        filenameItem.textContent = String(name);
        filenameList.appendChild(filenameItem);
      });
    }

    $("detail-type").textContent = content.media_type || "application/octet-stream";
    $("detail-size").textContent = fmtBytes(content.size_bytes);

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

document.querySelectorAll(".copy-button").forEach(bindCopyButton);
loadNetworkInfo();
