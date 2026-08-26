"use strict";

const ICE_SERVERS = [
  { urls: "stun:stun.l.google.com:19302" },
  { urls: "stun:global.stun.twilio.com:3478" },
];

const elements = {
  status: document.querySelector("#connectionStatus"),
  displayName: document.querySelector("#displayName"),
  createOffer: document.querySelector("#createOfferButton"),
  offerOutput: document.querySelector("#offerOutput"),
  copyOffer: document.querySelector("#copyOfferButton"),
  offerInput: document.querySelector("#offerInput"),
  acceptOffer: document.querySelector("#acceptOfferButton"),
  answerOutput: document.querySelector("#answerOutput"),
  copyAnswer: document.querySelector("#copyAnswerButton"),
  answerInput: document.querySelector("#answerInput"),
  completeConnection: document.querySelector("#completeConnectionButton"),
  peerSummary: document.querySelector("#peerSummary"),
  latency: document.querySelector("#latencyLabel"),
  disconnect: document.querySelector("#disconnectButton"),
  messageList: document.querySelector("#messageList"),
  messageForm: document.querySelector("#messageForm"),
  messageInput: document.querySelector("#messageInput"),
  sendButton: document.querySelector("#sendButton"),
};

let peerConnection = null;
let dataChannel = null;
let heartbeatTimer = null;
let pendingCandidates = [];
let localIdentity = null;
let remoteIdentity = null;
let lastHeartbeatSent = 0;

function randomId() {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function defaultName() {
  return "节点-" + randomId().slice(0, 4);
}

function setStatus(text, mode) {
  elements.status.textContent = text;
  elements.status.className = "status-chip " + mode;
}

function setChatEnabled(enabled) {
  elements.messageInput.disabled = !enabled;
  elements.sendButton.disabled = !enabled;
  elements.disconnect.disabled = !peerConnection;
}

function appendMessage(kind, sender, body) {
  const item = document.createElement("li");
  if (kind === "system" || kind === "error") {
    item.className = kind + "-message";
    item.textContent = body;
  } else {
    item.className = kind;
    const meta = document.createElement("span");
    meta.className = "meta";
    meta.textContent = sender + " · " + new Date().toLocaleTimeString("zh-CN");
    const bubble = document.createElement("div");
    bubble.className = "bubble";
    bubble.textContent = body;
    item.append(meta, bubble);
  }
  elements.messageList.append(item);
  elements.messageList.scrollTop = elements.messageList.scrollHeight;
}

async function compressedJson(payload) {
  const stream = new Blob([JSON.stringify(payload)]).stream().pipeThrough(new CompressionStream("gzip"));
  const buffer = await new Response(stream).arrayBuffer();
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

async function decompressedJson(base64) {
  const bytes = Uint8Array.from(atob(base64.trim()), (char) => char.charCodeAt(0));
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
  const buffer = await new Response(stream).arrayBuffer();
  return JSON.parse(new TextDecoder().decode(buffer));
}

function cleanupConnection() {
  clearInterval(heartbeatTimer);
  heartbeatTimer = null;
  if (dataChannel) {
    dataChannel.onopen = dataChannel.onclose = dataChannel.onmessage = null;
    if (dataChannel.readyState !== "closed") dataChannel.close();
  }
  if (peerConnection) peerConnection.close();
  dataChannel = null;
  peerConnection = null;
  pendingCandidates = [];
  remoteIdentity = null;
  setChatEnabled(false);
}

function bindDataChannel(channel) {
  dataChannel = channel;
  channel.binaryType = "arraybuffer";

  channel.addEventListener("open", () => {
    setStatus("已连接", "online");
    setChatEnabled(true);
    appendMessage("system", null, "与 " + (remoteIdentity?.name || "对端节点") + " 的加密通道已建立");
    sendEnvelope({ type: "hello", name: localIdentity.name });
    lastHeartbeatSent = Date.now();
    heartbeatTimer = setInterval(sendHeartbeat, 5000);
  });

  channel.addEventListener("message", (event) => {
    try {
      handleEnvelope(JSON.parse(event.data));
    } catch {
      appendMessage("error", null, "收到无法解析的数据包");
    }
  });

  channel.addEventListener("close", () => {
    setStatus("已断开", "offline");
    elements.peerSummary.textContent = "尚未连接任何节点。";
    elements.latency.textContent = "— ms";
    appendMessage("system", null, "连接已关闭");
    cleanupConnection();
  });

  channel.addEventListener("error", () => appendMessage("error", null, "数据通道发生错误"));
}

function sendEnvelope(envelope) {
  if (!dataChannel || dataChannel.readyState !== "open") return false;
  try {
    dataChannel.send(JSON.stringify(envelope));
    return true;
  } catch {
    appendMessage("error", null, "消息发送失败：缓冲区不可用");
    return false;
  }
}

function sendHeartbeat() {
  if (!dataChannel || dataChannel.readyState !== "open") return;
  if (Date.now() - lastHeartbeatSent < 4500) return;
  lastHeartbeatSent = Date.now();
  sendEnvelope({ type: "ping", at: Date.now() });
}

function handleEnvelope(envelope) {
  switch (envelope.type) {
    case "hello":
      remoteIdentity = { ...remoteIdentity, name: String(envelope.name || "未知节点").slice(0, 24) };
      elements.peerSummary.textContent = "已连接：" + remoteIdentity.name;
      break;
    case "chat": {
      const text = String(envelope.text || "").slice(0, 2000);
      const name = remoteIdentity?.name || String(envelope.name || "对端节点").slice(0, 24);
      appendMessage("remote", name, text);
      break;
    }
    case "ping":
      sendEnvelope({ type: "pong", at: envelope.at });
      break;
    case "pong":
      elements.latency.textContent = Math.max(0, Date.now() - Number(envelope.at)) + " ms";
      break;
    default:
      break;
  }
}

function createPeerConnection() {
  cleanupConnection();
  peerConnection = new RTCPeerConnection({ iceServers: ICE_SERVERS });
  peerConnection.onicecandidate = ({ candidate }) => {
    if (candidate) pendingCandidates.push(candidate.toJSON());
  };
  peerConnection.onconnectionstatechange = () => {
    if (peerConnection.connectionState === "connecting") setStatus("正在连接...", "connecting");
    if (peerConnection.connectionState === "failed") {
      setStatus("连接失败", "offline");
      appendMessage("error", null, "WebRTC 连接失败。请检查网络或尝试更换网络环境。");
      cleanupConnection();
    }
  };
  localIdentity = { id: randomId(), name: elements.displayName.value.trim() || defaultName() };
  return peerConnection;
}

async function waitForIceGathering(connection) {
  if (connection.iceGatheringState === "complete") return;
  await new Promise((resolve) => {
    const timeout = setTimeout(resolve, 2500);
    connection.addEventListener("icegatheringstatechange", () => {
      if (connection.iceGatheringState === "complete") {
        clearTimeout(timeout);
        resolve();
      }
    });
  });
}

elements.createOffer.addEventListener("click", async () => {
  try {
    const connection = createPeerConnection();
    bindDataChannel(connection.createDataChannel("meshtalk", { ordered: true }));
    const offer = await connection.createOffer();
    await connection.setLocalDescription(offer);
    await waitForIceGathering(connection);
    const payload = { v: 1, app: "meshtalk", identity: localIdentity, sdp: connection.localDescription.sdp, candidates: pendingCandidates };
    elements.offerOutput.value = await compressedJson(payload);
    setStatus("等待回复码", "connecting");
    appendMessage("system", null, "邀请码已生成。请发送给对方，然后粘贴对方的回复码。");
  } catch (error) {
    appendMessage("error", null, "创建邀请码失败：" + error.message);
    cleanupConnection();
  }
});

elements.acceptOffer.addEventListener("click", async () => {
  try {
    const invitation = await decompressedJson(elements.offerInput.value);
    if (invitation.app !== "meshtalk" || !invitation.sdp) throw new Error("邀请码格式无效");
    const connection = createPeerConnection();
    remoteIdentity = invitation.identity || null;
    connection.ondatachannel = (event) => bindDataChannel(event.channel);
    await connection.setRemoteDescription({ type: "offer", sdp: invitation.sdp });
    for (const candidate of invitation.candidates || []) {
      await connection.addIceCandidate(candidate).catch(() => {});
    }
    const answer = await connection.createAnswer();
    await connection.setLocalDescription(answer);
    await waitForIceGathering(connection);
    const payload = { v: 1, app: "meshtalk", identity: localIdentity, sdp: connection.localDescription.sdp, candidates: pendingCandidates };
    elements.answerOutput.value = await compressedJson(payload);
    setStatus("等待连接确认", "connecting");
    appendMessage("system", null, "回复码已生成。请返回给发起方。");
  } catch (error) {
    appendMessage("error", null, "加入房间失败：" + error.message);
    cleanupConnection();
  }
});

elements.completeConnection.addEventListener("click", async () => {
  if (!peerConnection || !elements.offerOutput.value) {
    appendMessage("error", null, "请先创建邀请码，再粘贴回复码");
    return;
  }
  try {
    const reply = await decompressedJson(elements.answerInput.value);
    if (reply.app !== "meshtalk" || !reply.sdp) throw new Error("回复码格式无效");
    remoteIdentity = reply.identity || remoteIdentity;
    if (remoteIdentity) elements.peerSummary.textContent = "正在连接：" + remoteIdentity.name;
    await peerConnection.setRemoteDescription({ type: "answer", sdp: reply.sdp });
    for (const candidate of reply.candidates || []) {
      await peerConnection.addIceCandidate(candidate).catch(() => {});
    }
    setStatus("正在握手", "connecting");
  } catch (error) {
    appendMessage("error", null, "连接失败：" + error.message);
  }
});

async function copyText(source, label) {
  const value = source.value.trim();
  if (!value) {
    appendMessage("system", null, label + "还没有生成");
    return;
  }
  try {
    await navigator.clipboard.writeText(value);
    appendMessage("system", null, label + "已复制");
  } catch {
    source.select();
    appendMessage("system", null, "请按 Ctrl+C 手动复制");
  }
}

elements.copyOffer.addEventListener("click", () => copyText(elements.offerOutput, "邀请码"));
elements.copyAnswer.addEventListener("click", () => copyText(elements.answerOutput, "回复码"));

elements.messageForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const text = elements.messageInput.value.replace(/\s+$/u, "").trim();
  if (!text || !sendEnvelope({ type: "chat", name: localIdentity?.name, text })) return;
  appendMessage("self", localIdentity.name + "（我）", text);
  elements.messageInput.value = "";
  elements.messageInput.focus();
});

elements.disconnect.addEventListener("click", () => {
  sendEnvelope({ type: "bye" });
  cleanupConnection();
  setStatus("离线", "offline");
  appendMessage("system", null, "你已主动断开连接");
});

document.querySelector("#helpButton").addEventListener("click", () => document.querySelector("#helpDialog").showModal());
elements.displayName.addEventListener("input", () => {
  if (localIdentity) localIdentity.name = elements.displayName.value.trim() || defaultName();
});
window.addEventListener("beforeunload", cleanupConnection);
setChatEnabled(false);
setStatus("离线", "offline");
appendMessage("system", null, "欢迎来到 MeshTalk。先在上方交换邀请码和回复码，即可开始私密聊天。");
