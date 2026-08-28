// 网络接入地址的纯函数模块。
// 这些函数不读取 DOM、不访问 localStorage，浏览器页面和 Node 测试共用同一份规则。

// normalizeHostname 统一去掉浏览器可能返回的 IPv6 方括号。
export function normalizeHostname(value) {
  return String(value || "").replace(/^\[|\]$/g, "");
}

// isIPv4Literal 判断字符串是否是四段十进制 IPv4 地址。
export function isIPv4Literal(hostname) {
  var parts = normalizeHostname(hostname).split(".");
  if (parts.length !== 4) return false;
  for (var i = 0; i < parts.length; i += 1) {
    if (!/^\d+$/.test(parts[i])) return false;
    var value = Number(parts[i]);
    if (value < 0 || value > 255) return false;
  }
  return true;
}

// isLoopbackHostname 只识别本机开发页面允许使用裸 WS 的 loopback 主机。
export function isLoopbackHostname(hostname) {
  var host = normalizeHostname(hostname).toLowerCase();
  if (host === "localhost" || host === "::1") return true;
  if (isIPv4Literal(host) && Number(host.split(".")[0]) === 127) return true;
  return /^::ffff:127(?:\.|$)/.test(host);
}

// multiaddrHost 按浏览器 hostname 形态选择 ip4、ip6 或 dns4 协议段。
export function multiaddrHost(hostname) {
  var host = normalizeHostname(hostname);
  if (!host) throw new Error("当前页面没有可用的 hostname");
  if (isIPv4Literal(host)) return "/ip4/" + host;
  if (host.indexOf(":") !== -1) return "/ip6/" + host;
  return "/dns4/" + host;
}

// currentBrowserNetworkAddress 使用当前页面 URL 生成 WSS/开发 WS 地址。
// locationLike 只需要 protocol、hostname、port 三个字段，便于脱离浏览器测试。
export function currentBrowserNetworkAddress(locationLike, peerID) {
  var location = locationLike || {};
  var protocol = String(location.protocol || "").toLowerCase();
  var hostname = normalizeHostname(location.hostname);
  var port = String(location.port || "");
  if (!port) port = protocol === "https:" ? "443" : "80";

  if (protocol === "https:") {
    return multiaddrHost(hostname) + "/tcp/" + port + "/tls/ws/p2p/" + peerID;
  }
  if (protocol === "http:" && isLoopbackHostname(hostname)) {
    return multiaddrHost(hostname) + "/tcp/" + port + "/ws/p2p/" + peerID;
  }
  throw new Error("公网浏览器必须使用 HTTPS/WSS");
}

// validateNetworkPayload 校验公开 API 的最小响应，并提取 Direct 地址 hostname。
export function validateNetworkPayload(data) {
  var peerID = String(data && data.peer_id || "").trim();
  var publicKey = String(data && data.supplier_public_key || "").trim();
  if (!peerID) throw new Error("服务端未返回 NAS PeerId");
  if (!/^0[23][0-9a-fA-F]{64}$/.test(publicKey)) {
    throw new Error("服务端未返回合法的 33 字节压缩公钥");
  }

  var values = data && data.webrtc_direct_addresses;
  if (!Array.isArray(values)) throw new Error("服务端返回的 WebRTC Direct 地址列表格式不正确");
  var direct = [];
  var pattern = /^\/(ip4|ip6|dns4|dns6)\/([^/]+)\/udp\/([1-9][0-9]{0,4})\/webrtc-direct\/certhash\/([^/]+)\/p2p\/([^/]+)$/;
  values.forEach(function (value) {
    if (typeof value !== "string") throw new Error("服务端返回的 WebRTC Direct 地址不完整或不合法");
    var match = value.match(pattern);
    if (!match || Number(match[3]) > 65535 || match[5] !== peerID) {
      throw new Error("服务端返回的 WebRTC Direct 地址不完整或不合法");
    }
    direct.push({ value: value, hostname: normalizeHostname(match[2]) });
  });
  return { peerID: peerID, publicKey: publicKey, direct: direct };
}

// hasSameHostname 判断 WSS 页面 hostname 与 Direct 公布地址是否相同。
export function hasSameHostname(browserHostname, directAddresses) {
  var browserHost = normalizeHostname(browserHostname).toLowerCase();
  return (directAddresses || []).some(function (item) {
    return normalizeHostname(item && item.hostname).toLowerCase() === browserHost;
  });
}
