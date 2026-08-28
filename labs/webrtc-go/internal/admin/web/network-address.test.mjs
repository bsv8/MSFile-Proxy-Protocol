// G12-G14：WSS 地址生成、HTTP 门禁与相同 hostname 提示的 Node 单元测试。
import test from "node:test";
import assert from "node:assert/strict";

import {
  currentBrowserNetworkAddress,
  hasSameHostname,
  validateNetworkPayload
} from "./network-address.mjs";

const peerID = "12D3KooWNetworkTestPeer";
const publicKey = "02" + "ab".repeat(32);

test("G12: HTTPS 域名默认使用 443 生成 WSS", () => {
  assert.equal(
    currentBrowserNetworkAddress({ protocol: "https:", hostname: "nas.example.com", port: "" }, peerID),
    "/dns4/nas.example.com/tcp/443/tls/ws/p2p/" + peerID
  );
});

test("G12: IPv4、IPv6 和显式 HTTPS 端口使用正确协议段", () => {
  assert.equal(
    currentBrowserNetworkAddress({ protocol: "https:", hostname: "203.0.113.10", port: "8443" }, peerID),
    "/ip4/203.0.113.10/tcp/8443/tls/ws/p2p/" + peerID
  );
  assert.equal(
    currentBrowserNetworkAddress({ protocol: "https:", hostname: "[2001:db8::10]", port: "" }, peerID),
    "/ip6/2001:db8::10/tcp/443/tls/ws/p2p/" + peerID
  );
});

test("G13: loopback HTTP 可用于开发 WS，公网 HTTP 必须拒绝", () => {
  assert.equal(
    currentBrowserNetworkAddress({ protocol: "http:", hostname: "127.0.0.1", port: "8080" }, peerID),
    "/ip4/127.0.0.1/tcp/8080/ws/p2p/" + peerID
  );
  assert.equal(
    currentBrowserNetworkAddress({ protocol: "http:", hostname: "localhost", port: "" }, peerID),
    "/dns4/localhost/tcp/80/ws/p2p/" + peerID
  );
  assert.throws(
    () => currentBrowserNetworkAddress({ protocol: "http:", hostname: "nas.example.com", port: "80" }, peerID),
    { message: "公网浏览器必须使用 HTTPS/WSS" }
  );
});

test("G14: Direct 与当前页面 hostname 相同则返回提示所需结果", () => {
  const network = validateNetworkPayload({
    peer_id: peerID,
    supplier_public_key: publicKey,
    webrtc_direct_addresses: [
      "/dns4/nas.example.com/udp/4001/webrtc-direct/certhash/cert-hash/p2p/" + peerID,
      "/ip4/203.0.113.10/udp/4002/webrtc-direct/certhash/cert-hash/p2p/" + peerID
    ]
  });

  assert.equal(hasSameHostname("NAS.EXAMPLE.COM", network.direct), true);
  assert.equal(hasSameHostname("other.example.com", network.direct), false);
});
