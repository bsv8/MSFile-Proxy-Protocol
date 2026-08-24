import { spawn } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'
import { chromium } from 'playwright'

const scriptDir = dirname(fileURLToPath(import.meta.url))
const webDir = resolve(scriptDir, '..')
const goDir = resolve(webDir, '../webrtc-go')

const pageURL = process.env.MSFILE_E2E_PAGE_URL ?? 'https://msfile-proxy-protocol.pages.dev/'
const nasPublicIP = process.env.MSFILE_E2E_NAS_PUBLIC_IP ?? '23.254.242.181'
const ports = (process.env.MSFILE_E2E_PORTS ?? '4001,3478,8443')
  .split(',')
  .map((value) => Number.parseInt(value.trim(), 10))
const keyFile = process.env.MSFILE_E2E_IDENTITY_KEY_FILE ?? join(goDir, 'nas-test.key')
const skipGo = process.env.MSFILE_E2E_SKIP_GO === 'true'
const expectedPublicKey = process.env.MSFILE_E2E_NAS_PUBLIC_KEY ??
  '03efefcf883fa26a730a1af2b873b09cb7dda8a91eb4738fb638c647bbc2151956'
const expectedPeerID = process.env.MSFILE_E2E_NAS_PEER_ID ??
  '16Uiu2HAmUobt18vmGmzAV8Jf3cK8P1jKSwDuDAso5haLfoYidkQ5'
const expectedCerthash = process.env.MSFILE_E2E_NAS_CERTHASH ??
  'uEiBl68na55pk4ziuFvXvb1G5ps7l-VpnKDUHo0WbPVLQpQ'

assert(ports.length > 0 && ports.every((port) => Number.isInteger(port) && port > 0 && port <= 65535),
  'MSFILE_E2E_PORTS 必须是逗号分隔的合法 UDP 端口')

function run(command, args, options = {}) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, { ...options, stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk) => { stdout += chunk })
    child.stderr.on('data', (chunk) => { stderr += chunk })
    child.once('error', rejectRun)
    child.once('exit', (code, signal) => {
      if (code === 0) {
        resolveRun({ stdout, stderr })
        return
      }
      rejectRun(new Error(`${command} 退出异常：code=${code}, signal=${signal}\n${stdout}\n${stderr}`))
    })
  })
}

function parseJSONLines(text) {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.startsWith('{'))
    .flatMap((line) => {
      try {
        return [JSON.parse(line)]
      } catch {
        return []
      }
    })
}

async function waitForGoEvent(getLines, event, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const record = parseJSONLines(getLines()).find((entry) => entry.event === event)
    if (record != null) return record
    await new Promise((resolveWait) => setTimeout(resolveWait, 50))
  }
  throw new Error(`等待 Go 事件 ${event} 超时；日志：\n${getLines()}`)
}

async function browserRecords(page) {
  const lines = await page.locator('#log-pane .log-line').allTextContents()
  return parseJSONLines(lines.join('\n'))
}

async function waitForBrowserEvent(page, event, timeoutMs = 30_000) {
  await page.waitForFunction((expectedEvent) => {
    return [...document.querySelectorAll('#log-pane .log-line')].some((element) => {
      try {
        return JSON.parse(element.textContent ?? '').event === expectedEvent
      } catch {
        return false
      }
    })
  }, event, { timeout: timeoutMs })
}

async function waitForBrowserFlow(page) {
  await page.waitForFunction(() => {
    const records = [...document.querySelectorAll('#log-pane .log-line')].flatMap((element) => {
      try {
        return [JSON.parse(element.textContent ?? '')]
      } catch {
        return []
      }
    })
    return records.some((record) => record.event === 'direct_flow_failed') ||
      records.filter((record) => record.event === 'echo_result').length >= 4
  }, undefined, { timeout: 50_000 })
}

async function testPort(browser, port) {
  const context = await browser.newContext()
  const page = await context.newPage()
  const consoleErrors = []
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text())
  })
  page.on('pageerror', (error) => consoleErrors.push(error.message))

  try {
    await page.goto(pageURL, { waitUntil: 'networkidle', timeout: 30_000 })
    await page.locator('#btn-generate-key').click()
    await waitForBrowserEvent(page, 'identity_activated')
    await page.locator('#btn-start-node').click()
    await waitForBrowserEvent(page, 'node_started')

    const target = `/ip4/${nasPublicIP}/udp/${port}/webrtc-direct/certhash/${expectedCerthash}/p2p/${expectedPeerID}`
    await page.locator('#input-nas-multiaddr').fill(target)
    await page.locator('#input-nas-pubkey').fill(expectedPublicKey)
    await page.locator('#btn-direct-dial').click()
    await waitForBrowserFlow(page)

    const records = await browserRecords(page)
    const failed = records.find((record) => record.event === 'direct_flow_failed')
    assert.equal(failed, undefined, `UDP ${port} 浏览器直连失败：${failed?.error_code ?? '未知错误'}`)

    const gate = records.find((record) => record.event === 'direct_gate_passed')
    assert(gate != null, `UDP ${port} 缺少 direct_gate_passed`)
    assert.equal(gate.remote_peer_id, expectedPeerID, `UDP ${port} NAS PeerId 不一致`)
    assert.equal(gate.transport, 'webrtc-direct', `UDP ${port} transport 不是 webrtc-direct`)
    assert.equal(gate.direct, true, `UDP ${port} connection.direct 不是 true`)

    const identity = records.find((record) => record.event === 'identity_protocol_done')
    assert.deepEqual(identity?.problems, [], `UDP ${port} identity 协议校验失败`)

    const echoes = records.filter((record) => record.event === 'echo_result')
    assert.deepEqual(echoes.map((record) => record.bytes_sent), [0, 1, 16384, 262144],
      `UDP ${port} echo 测试尺寸不完整`)
    assert(echoes.every((record) => record.matches === true), `UDP ${port} echo 内容不一致`)

    return {
      port,
      target,
      remote_peer_id: gate.remote_peer_id,
      transport: gate.transport,
      direct: gate.direct,
      candidate_pair: gate.candidate_pair,
      identity_problems: identity.problems,
      echo_bytes: echoes.map((record) => record.bytes_sent),
      console_errors: consoleErrors
    }
  } finally {
    await context.close()
  }
}

const tempDir = await mkdtemp(join(tmpdir(), 'msfile-webrtc-e2e-'))
const binary = join(tempDir, 'msfile-webrtc-lab')
let nasProcess
let browser
let goStdout = ''
let goStderr = ''

try {
  if (!skipGo) {
    await run('go', ['build', '-o', binary, './cmd/msfile-webrtc-lab'], { cwd: goDir })

    const nasArgs = [
      'nas',
      '--identity-key-file', keyFile,
      ...ports.flatMap((port) => ['--listen', `/ip4/0.0.0.0/udp/${port}/webrtc-direct`])
    ]
    nasProcess = spawn(binary, nasArgs, {
      cwd: goDir,
      env: {
        ...process.env,
        GOLOG_LOG_LEVEL: 'error',
        GOLOG_LOG_FORMAT: 'json',
        GOLOG_LOG_ADD_SOURCE: 'false'
      },
      stdio: ['ignore', 'pipe', 'pipe']
    })
    nasProcess.stdout.on('data', (chunk) => { goStdout += chunk })
    nasProcess.stderr.on('data', (chunk) => { goStderr += chunk })
    nasProcess.once('exit', (code, signal) => {
      if (code !== 0 && signal !== 'SIGINT') {
        process.stderr.write(`Go NAS 提前退出：code=${code}, signal=${signal}\n${goStdout}\n${goStderr}\n`)
      }
    })

    await waitForGoEvent(() => goStdout, 'nas_started')
    await waitForGoEvent(() => goStdout, 'lab_protocols_registered')
  }

  browser = await chromium.launch({ headless: true })
  const results = []
  for (const port of ports) {
    process.stdout.write(`${JSON.stringify({ event: 'direct_e2e_port_started', port, note_zh: '开始浏览器全链路测试' })}\n`)
    const result = await testPort(browser, port)
    results.push(result)
    process.stdout.write(`${JSON.stringify({ event: 'direct_e2e_port_passed', port, note_zh: '直连、身份与四组 echo 全部通过' })}\n`)
  }

  if (!skipGo) {
    const goRecords = parseJSONLines(goStdout)
    const servedIdentity = goRecords.filter((record) =>
      record.event === 'lab_protocol_served' && record.protocol === '/msfile-lab/identity/1.0.0')
    const servedEcho = goRecords.filter((record) =>
      record.event === 'lab_protocol_served' && record.protocol === '/msfile-lab/echo/1.0.0')
    assert(servedIdentity.length >= ports.length, 'Go 端 identity 协议处理次数不足')
    assert(servedEcho.length >= ports.length * 4, 'Go 端 echo 协议处理次数不足')
  }

  process.stdout.write(`${JSON.stringify({
    event: 'direct_e2e_passed',
    note_zh: '真实 Chromium 已完成 WebRTC Direct、Noise 身份、identity 与四组 echo 全链路',
    page_url: pageURL,
    nas_mode: skipGo ? 'external' : '由测试脚本启动',
    ports: results
  }, null, 2)}\n`)
} finally {
  await browser?.close().catch(() => {})
  if (nasProcess != null && nasProcess.exitCode == null) {
    nasProcess.kill('SIGINT')
    await new Promise((resolveWait) => {
      const timer = setTimeout(() => {
        if (nasProcess.exitCode == null) nasProcess.kill('SIGKILL')
        resolveWait()
      }, 5_000)
      nasProcess.once('exit', () => {
        clearTimeout(timer)
        resolveWait()
      })
    })
  }
  await rm(tempDir, { recursive: true, force: true })
}
