"use strict";

const PROTOCOL_VERSION = 3;
const MAX_MESSAGE_CACHE = 1500;
const BASE_ICE_SERVERS = [
  { urls: "stun:stun.l.google.com:19302" },
  { urls: "stun:global.stun.twilio.com:3478" }
];

const elements = {
  status: document.querySelector("#connectionStatus"),
  displayName: document.querySelector("#displayName"),
  roomSecret: document.querySelector("#roomSecret"),
  turnUrls: document.querySelector("#turnUrls"),
  turnUsername: document.querySelector("#turnUsername"),
  turnCredential: document.querySelector("#turnCredential"),
  saveNetwork: document.querySelector("#saveNetworkButton"),
  encryptionStatus: document.querySelector("#encryptionStatus"),
  createOffer: document.querySelector("#createOfferButton"),
  offerOutput: document.querySelector("#offerOutput"),
  offerInput: document.querySelector("#offerInput"),
  acceptOffer: document.querySelector("#acceptOfferButton"),
  answerOutput: document.querySelector("#answerOutput"),
  answerInput: document.querySelector("#answerInput"),
  completeConnection: document.querySelector("#completeConnectionButton"),
  invitationList: document.querySelector("#invitationList"),
  memberCount: document.querySelector("#memberCountLabel"),
  latencyLabel: document.querySelector("#latencyLabel"),
  memberList: document.querySelector("#memberList"),
  pendingConnections: document.querySelector("#pendingConnections"),
  disconnect: document.querySelector("#disconnectButton"),
  messageList: document.querySelector("#messageList"),
  messageForm: document.querySelector("#messageForm"),
  messageInput: document.querySelector("#messageInput"),
  sendButton: document.querySelector("#sendButton")
};

const sessions = new Map();
const invitations = new Map();
const seenMessages = new Set();
let localIdentity = null;
let heartbeatTimer = null;
let cryptoKey = null;

function randomId() {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, function(byte) {
    return byte.toString(16).padStart(2, "0");
  }).join("");
}

function safeText(value, maxLength) {
  return String(value || "").replace(/[\u0000-\u001f\u007f]/g, "").slice(0, maxLength);
}

function defaultName() {
  return "节点-" + randomId().slice(0, 4);
}

function ensureLocalIdentity() {
  if (!localIdentity) {
    localIdentity = {
      id: randomId(),
      name: elements.displayName.value.trim() || defaultName()
    };
  }
  return localIdentity;
}

async function deriveKey(secret) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode("meshtalk-v3-room-salt"),
      iterations: 210000,
      hash: "SHA-256"
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptJson(envelope) {
  if (!cryptoKey) return envelope;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    new TextEncoder().encode(JSON.stringify(envelope))
  ));
  return {
    encrypted: true,
    iv: btoa(String.fromCharCode.apply(null, iv)),
    data: btoa(String.fromCharCode.apply(null, cipher))
  };
}

async function decryptJson(rawEnvelope) {
  if (!rawEnvelope.encrypted) return rawEnvelope;
  if (!cryptoKey) throw new Error("missing room key");
  const iv = Uint8Array.from(atob(rawEnvelope.iv), function(char) { return char.charCodeAt(0); });
  const data = Uint8Array.from(atob(rawEnvelope.data), function(char) { return char.charCodeAt(0); });
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, data);
  return JSON.parse(new TextDecoder().decode(plain));
}

function iceServers() {
  const servers = BASE_ICE_SERVERS.slice();
  const urls = safeText(elements.turnUrls.value, 300).trim();
  if (urls) {
    for (const url of urls.split(/[\s,]+/)) {
      servers.push({
        urls: url,
        username: safeText(elements.turnUsername.value, 128),
        credential: String(elements.turnCredential.value || "").slice(0, 256)
      });
    }
  }
  return servers;
}

function updateCryptoState() {
  const secret = elements.roomSecret.value;
  if (secret.length < 8) {
    cryptoKey = null;
    elements.encryptionStatus.textContent = "应用层加密未启用";
    elements.encryptionStatus.className = "security-chip disabled";
    return Promise.resolve(false);
  }
  return deriveKey(secret).then(function(key) {
    const wasEnabled = Boolean(cryptoKey);
    cryptoKey = key;
    elements.encryptionStatus.textContent = "应用层 AES-256-GCM 已启用";
    elements.encryptionStatus.className = "security-chip enabled";
    if (!wasEnabled) appendMessage("system", null, "应用层端到端加密已启用。");
    return true;
  }).catch(function(error) {
    cryptoKey = null;
    elements.encryptionStatus.textContent = "密钥派生失败";
    elements.encryptionStatus.className = "security-chip disabled";
    appendMessage("error", null, "密钥派生失败：" + error.message);
    return false;
  });
}

function saveNetworkSettings() {
  try {
    localStorage.setItem("meshtalk.network", JSON.stringify({
      turnUrls: safeText(elements.turnUrls.value, 300),
      turnUsername: safeText(elements.turnUsername.value, 128),
      turnCredential: String(elements.turnCredential.value || "").slice(0, 256)
    }));
    appendMessage("system", null, "网络设置已保存到本机浏览器。");
  } catch {
    appendMessage("error", null, "无法保存网络设置：浏览器存储不可用");
  }
}

function loadNetworkSettings() {
  try {
    const settings = JSON.parse(localStorage.getItem("meshtalk.network") || "{}");
    if (settings.turnUrls) elements.turnUrls.value = safeText(settings.turnUrls, 300);
    if (settings.turnUsername) elements.turnUsername.value = safeText(settings.turnUsername, 128);
    if (settings.turnCredential) elements.turnCredential.value = String(settings.turnCredential).slice(0, 256);
  } catch {}
}

function setStatus(text, mode) {
  elements.status.textContent = text;
  elements.status.className = "status-chip " + mode;
}

function connectedSessions() {
  return Array.from(sessions.values()).filter(function(session) {
    return session.state === "connected";
  });
}

function refreshInvitations() {
  elements.invitationList.innerHTML = "";
  if (invitations.size === 0) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = "暂无记录。生成邀请码后会在这里按目标节点保存。";
    elements.invitationList.append(empty);
    return;
  }
  invitations.forEach(function(record, targetId) {
    const item = document.createElement("div");
    item.className = "invitation-item";
    const title = document.createElement("div");
    title.className = "invitation-title";
    const name = document.createElement("strong");
    name.textContent = record.name ? safeText(record.name, 24) : "节点 " + targetId.slice(0, 6);
    const state = document.createElement("span");
    state.className = "invitation-state " + record.state;
    state.textContent = record.state === "connected" ? "已连接" :
      record.state === "answered" ? "回复码待应用" : "等待对方回复码";
    title.append(name, state);
    item.append(title, document.createTextNode("目标：" + targetId.slice(0, 10)));
    elements.invitationList.append(item);
  });
}

function refreshInterface() {
  const connected = connectedSessions();
  elements.memberCount.textContent = (connected.length + 1) + " 人";

  elements.memberList.innerHTML = "";
  appendMember(localIdentity.name + "（我）");
  connected.forEach(function(session) {
    appendMember(session.name + (session.latency == null ? "" : " · " + session.latency + "ms"));
  });

  if (connected.length > 0) {
    setStatus("群聊中 · " + connected.length + " 个直连节点", "online");
  } else if (sessions.size > 0) {
    setStatus("正在建立连接...", "connecting");
  } else {
    setStatus("离线", "offline");
  }

  const latencies = connected.filter(function(session) { return session.latency != null; });
  if (latencies.length) {
    const average = Math.round(latencies.reduce(function(total, session) {
      return total + session.latency;
    }, 0) / latencies.length);
    elements.latencyLabel.textContent = average + " ms";
  } else {
    elements.latencyLabel.textContent = "— ms";
  }

  elements.pendingConnections.classList.toggle("visible", sessions.size > connected.length);
  elements.pendingConnections.innerHTML = "";
  sessions.forEach(function(session) {
    if (session.state !== "connected") {
      const item = document.createElement("div");
      item.className = "pending-item";
      item.textContent = "节点 " + session.targetId.slice(0, 6) + "：" + session.state;
      elements.pendingConnections.append(item);
    }
  });

  const enabled = connected.length > 0;
  elements.messageInput.disabled = !enabled;
  elements.sendButton.disabled = !enabled;
  elements.disconnect.disabled = sessions.size === 0;
  refreshInvitations();
}

function appendMember(name) {
  const item = document.createElement("li");
  item.className = "member-item";
  const dot = document.createElement("span");
  dot.className = "member-dot";
  item.append(dot, document.createTextNode(safeText(name, 42)));
  elements.memberList.append(item);
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
  return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)));
}

async function decompressedJson(base64) {
  const normalized = safeText(base64, 240000).replace(/\s+/g, "");
  const bytes = Uint8Array.from(atob(normalized), function(char) {
    return char.charCodeAt(0);
  });
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
  const buffer = await new Response(stream).arrayBuffer();
  return JSON.parse(new TextDecoder().decode(buffer));
}

function createSession(targetId, role) {
  ensureLocalIdentity();
  const connection = new RTCPeerConnection({ iceServers: iceServers() });
  const session = {
    targetId: targetId,
    role: role,
    connection: connection,
    channel: null,
    state: "new",
    name: "未知节点",
    candidates: [],
    latency: null
  };

  connection.onicecandidate = function(event) {
    if (event.candidate) session.candidates.push(event.candidate.toJSON());
  };
  connection.onconnectionstatechange = function() {
    if (connection.connectionState === "failed") {
      appendMessage("error", null, "与节点 " + session.targetId.slice(0, 6) + " 连接失败。请检查网络，或在严格 NAT 环境配置 TURN。");
      closeSession(session);
    } else if (connection.connectionState === "closed") {
      closeSession(session);
    }
    refreshInterface();
  };

  sessions.set(targetId, session);
  refreshInterface();
  return session;
}

async function waitForIceGathering(connection) {
  if (connection.iceGatheringState === "complete") return;
  await new Promise(function(resolve) {
    const timeout = setTimeout(resolve, 3000);
    connection.addEventListener("icegatheringstatechange", function() {
      if (connection.iceGatheringState === "complete") {
        clearTimeout(timeout);
        resolve();
      }
    });
  });
}

function bindChannel(session, channel) {
  session.channel = channel;
  channel.binaryType = "arraybuffer";

  channel.addEventListener("open", function() {
    session.state = "connected";
    appendMessage("system", null, "已加入群聊网络：节点 " + session.targetId.slice(0, 6));
    sendTo(session, helloEnvelope());
    refreshInterface();
  });

  channel.addEventListener("message", function(event) {
    decryptJson(JSON.parse(event.data)).then(function(envelope) {
      handleEnvelope(session, envelope);
    }).catch(function() {
      appendMessage("error", null, "收到无法解密或解析的数据包。请确认使用相同房间密钥。");
    });
  });

  channel.addEventListener("close", function() {
    appendMessage("system", null, "节点 " + session.name + " 已离开。");
    closeSession(session);
  });

  channel.addEventListener("error", function() {
    appendMessage("error", null, "数据通道发生错误。");
  });
}

function closeSession(session) {
  if (!session || !sessions.has(session.targetId)) return;
  if (session.channel && session.channel.readyState !== "closed") session.channel.close();
  session.connection.onicecandidate = null;
  session.connection.onconnectionstatechange = null;
  session.connection.ondatachannel = null;
  session.connection.close();
  sessions.delete(session.targetId);
  invitations.delete(session.targetId);
  refreshInterface();
}

function closeAllSessions() {
  Array.from(sessions.values()).forEach(closeSession);
  invitations.clear();
  refreshInterface();
}

function helloEnvelope() {
  return {
    type: "hello",
    senderId: localIdentity.id,
    senderName: localIdentity.name
  };
}

function sendTo(session, envelope) {
  if (!session.channel || session.channel.readyState !== "open") return Promise.resolve(false);
  return encryptJson(envelope).then(function(protectedEnvelope) {
    session.channel.send(JSON.stringify(protectedEnvelope));
    return true;
  }).catch(function() {
    return false;
  });
}

function broadcast(envelope, excludeTargetId) {
  let hasTarget = false;
  sessions.forEach(function(session) {
    if (session.targetId !== excludeTargetId) {
      hasTarget = true;
      sendTo(session, envelope);
    }
  });
  return hasTarget;
}

function rememberMessage(messageId) {
  seenMessages.add(messageId);
  if (seenMessages.size > MAX_MESSAGE_CACHE) {
    seenMessages.delete(seenMessages.values().next().value);
  }
}

function handleEnvelope(session, envelope) {
  if (!envelope || typeof envelope.type !== "string") return;

  if (envelope.type === "hello") {
    session.name = safeText(envelope.senderName, 24) || "未知节点";
    const invitation = invitations.get(session.targetId);
    if (invitation && invitation.state !== "connected") {
      invitation.name = session.name;
      invitation.state = "connected";
    }
    appendMessage("system", null, "节点身份确认：" + session.name);
    refreshInterface();
    return;
  }

  if (envelope.type === "chat") {
    const messageId = safeText(envelope.messageId, 64);
    if (!messageId || seenMessages.has(messageId)) return;
    rememberMessage(messageId);
    const senderName = safeText(envelope.senderName, 24) || "未知节点";
    const text = safeText(envelope.text, 2000);
    if (!text) return;
    appendMessage("remote", senderName, text);
    broadcast(envelope, session.targetId);
    return;
  }

  if (envelope.type === "ping") {
    sendTo(session, { type: "pong", at: Number(envelope.at) || Date.now() });
    return;
  }

  if (envelope.type === "pong" && Number.isFinite(Number(envelope.at))) {
    session.latency = Math.max(0, Date.now() - Number(envelope.at));
    refreshInterface();
    return;
  }

  if (envelope.type === "bye") {
    appendMessage("system", null, "节点 " + session.name + " 已主动退出。");
    closeSession(session);
  }
}

function startHeartbeat() {
  clearInterval(heartbeatTimer);
  heartbeatTimer = setInterval(function() {
    sessions.forEach(function(session) {
      sendTo(session, { type: "ping", at: Date.now() });
    });
  }, 5000);
}

elements.createOffer.addEventListener("click", async function() {
  try {
    ensureLocalIdentity();
    const targetId = randomId();
    const session = createSession(targetId, "initiator");
    bindChannel(session, session.connection.createDataChannel("meshtalk", { ordered: true }));
    const offer = await session.connection.createOffer();
    await session.connection.setLocalDescription(offer);
    await waitForIceGathering(session.connection);
    const code = await compressedJson({
      v: PROTOCOL_VERSION,
      app: "meshtalk",
      group: true,
      targetId: targetId,
      identity: localIdentity,
      sdp: session.connection.localDescription.sdp,
      candidates: session.candidates
    });
    invitations.set(targetId, { name: "", state: "waiting" });
    elements.offerOutput.value = code;
    await copyValue(code, "邀请码", true);
    refreshInterface();
  } catch (error) {
    appendMessage("error", null, "创建邀请码失败：" + error.message);
    refreshInterface();
  }
});

elements.acceptOffer.addEventListener("click", async function() {
  try {
    ensureLocalIdentity();
    const invitation = await decompressedJson(elements.offerInput.value);
    if (invitation.app !== "meshtalk" || !invitation.sdp || !invitation.targetId) {
      throw new Error("邀请码格式无效");
    }
    if (invitation.targetId === localIdentity.id) throw new Error("不能连接自己");
    if (sessions.has(invitation.targetId)) closeSession(sessions.get(invitation.targetId));

    const session = createSession(invitation.targetId, "responder");
    if (invitation.identity && invitation.identity.id !== localIdentity.id) {
      session.name = safeText(invitation.identity.name, 24) || "未知节点";
    }
    session.connection.ondatachannel = function(event) {
      bindChannel(session, event.channel);
    };
    await session.connection.setRemoteDescription({ type: "offer", sdp: invitation.sdp });
    for (const candidate of invitation.candidates || []) {
      await session.connection.addIceCandidate(candidate).catch(function() {});
    }
    const answer = await session.connection.createAnswer();
    await session.connection.setLocalDescription(answer);
    await waitForIceGathering(session.connection);
    const replyCode = await compressedJson({
      v: PROTOCOL_VERSION,
      app: "meshtalk",
      group: true,
      targetId: invitation.targetId,
      identity: localIdentity,
      sdp: session.connection.localDescription.sdp,
      candidates: session.candidates
    });
    elements.answerOutput.value = replyCode;
    await copyValue(replyCode, "回复码", true);
  } catch (error) {
    appendMessage("error", null, "加入房间失败：" + error.message);
  }
});

elements.completeConnection.addEventListener("click", async function() {
  try {
    const reply = await decompressedJson(elements.answerInput.value);
    if (reply.app !== "meshtalk" || !reply.sdp || !reply.targetId) throw new Error("回复码格式无效");
    const session = sessions.get(reply.targetId);
    if (!session || session.role !== "initiator") throw new Error("找不到对应邀请；请重新生成并交换邀请码");
    if (reply.identity) {
      session.name = safeText(reply.identity.name, 24) || "未知节点";
      const invitation = invitations.get(reply.targetId);
      if (invitation) invitation.name = session.name;
    }
    await session.connection.setRemoteDescription({ type: "answer", sdp: reply.sdp });
    for (const candidate of reply.candidates || []) {
      await session.connection.addIceCandidate(candidate).catch(function() {});
    }
    const invitation = invitations.get(reply.targetId);
    if (invitation) invitation.state = "answered";
    elements.answerInput.value = "";
    appendMessage("system", null, "回复码已应用，正在握手。");
    refreshInterface();
  } catch (error) {
    appendMessage("error", null, "连接失败：" + error.message);
  }
});

async function copyValue(value, label, quietWhenEmpty) {
  if (!value) {
    if (!quietWhenEmpty) appendMessage("system", null, label + "还没有生成");
    return false;
  }
  try {
    await navigator.clipboard.writeText(value);
    appendMessage("system", null, label + "已自动复制到剪贴板。");
    return true;
  } catch {
    appendMessage("system", null, label + "已显示在文本框中，请手动复制。");
    return false;
  }
}

elements.saveNetwork.addEventListener("click", saveNetworkSettings);
elements.roomSecret.addEventListener("input", updateCryptoState);

elements.messageForm.addEventListener("submit", async function(event) {
  event.preventDefault();
  const text = elements.messageInput.value.replace(/\s+$/u, "").trim();
  if (!text || connectedSessions().length === 0) return;
  const delivered = broadcast({
    type: "chat",
    messageId: randomId(),
    senderId: localIdentity.id,
    senderName: localIdentity.name,
    text: text
  }, null);
  if (!delivered) return;
  appendMessage("self", localIdentity.name + "（我）", text);
  elements.messageInput.value = "";
  elements.messageInput.focus();
});

elements.disconnect.addEventListener("click", function() {
  broadcast({ type: "bye" }, null);
  closeAllSessions();
  appendMessage("system", null, "你已断开所有群聊连接。");
});

document.querySelector("#helpButton").addEventListener("click", function() {
  document.querySelector("#helpDialog").showModal();
});

elements.displayName.addEventListener("input", function() {
  ensureLocalIdentity();
  localIdentity.name = elements.displayName.value.trim() || defaultName();
  broadcast(helloEnvelope(), null);
  refreshInterface();
});

window.addEventListener("beforeunload", function() {
  broadcast({ type: "bye" }, null);
  closeAllSessions();
  clearInterval(heartbeatTimer);
});

ensureLocalIdentity();
loadNetworkSettings();
startHeartbeat();
refreshInterface();
appendMessage("system", null, "欢迎来到 MeshTalk。建议先设置相同的房间密钥，再交换邀请码。");
