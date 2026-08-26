"use strict";

const ICE_SERVERS = [
  { urls: "stun:stun.l.google.com:19302" },
  { urls: "stun:global.stun.twilio.com:3478" },
];
const PROTOCOL_VERSION = 2;
const MAX_MESSAGE_CACHE = 1500;

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
  memberCount: document.querySelector("#memberCountLabel"),
  memberList: document.querySelector("#memberList"),
  pendingConnections: document.querySelector("#pendingConnections"),
  disconnect: document.querySelector("#disconnectButton"),
  messageList: document.querySelector("#messageList"),
  messageForm: document.querySelector("#messageForm"),
  messageInput: document.querySelector("#messageInput"),
  sendButton: document.querySelector("#sendButton")
};

const sessions = new Map();
const activeOffers = new Map();
const seenMessages = new Set();
let localIdentity = null;
let heartbeatTimer = null;

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

function setStatus(text, mode) {
  elements.status.textContent = text;
  elements.status.className = "status-chip " + mode;
}

function connectedSessions() {
  return Array.from(sessions.values()).filter(function(session) {
    return session.state === "connected";
  });
}

function refreshInterface() {
  const connected = connectedSessions();
  const connecting = sessions.size - connected.length;
  elements.memberCount.textContent = (connected.length + 1) + " 人";

  if (connected.length > 0) {
    const averageLatency = Math.round(connected.reduce(function(total, session) {
      return total + (session.latency || 0);
    }, 0) / connected.length);
    setStatus("群聊中 · " + connected.length + " 个直连节点", "online");
    elements.memberList.innerHTML = "";
    appendMember(localIdentity.name + "（我）");
    connected.forEach(function(session) {
      appendMember(session.name);
    });
  } else if (sessions.size > 0) {
    setStatus("正在建立 " + sessions.size + " 条连接...", "connecting");
    elements.memberList.innerHTML = "";
    appendMember(localIdentity ? localIdentity.name + "（我，等待连接）" : "我（等待连接）");
  } else {
    setStatus("离线", "offline");
    elements.memberList.innerHTML = "";
    appendMember(localIdentity ? localIdentity.name + "（我，未入网）" : "我（未入网）");
  }

  elements.pendingConnections.classList.toggle("visible", sessions.size > 0);
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
}

function appendMember(name) {
  const item = document.createElement("li");
  item.className = "member-item";
  const dot = document.createElement("span");
  dot.className = "member-dot";
  item.append(dot, document.createTextNode(safeText(name, 30)));
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
  const normalized = safeText(base64, 200000).replace(/\s+/g, "");
  const bytes = Uint8Array.from(atob(normalized), function(char) {
    return char.charCodeAt(0);
  });
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
  const buffer = await new Response(stream).arrayBuffer();
  return JSON.parse(new TextDecoder().decode(buffer));
}

function createSession(targetId, role) {
  ensureLocalIdentity();
  const connection = new RTCPeerConnection({ iceServers: ICE_SERVERS });
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
      appendMessage("error", null, "与节点 " + session.targetId.slice(0, 6) + " 的连接失败。");
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
    const timeout = setTimeout(resolve, 2500);
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
    try {
      handleEnvelope(session, JSON.parse(event.data));
    } catch {
      appendMessage("error", null, "收到无法解析的数据包");
    }
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
  if (session.channel) {
    session.channel.onopen = session.channel.onmessage = session.channel.onclose = null;
    if (session.channel.readyState !== "closed") session.channel.close();
  }
  if (session.connection) {
    session.connection.onicecandidate = null;
    session.connection.onconnectionstatechange = null;
    session.connection.ondatachannel = null;
    session.connection.close();
  }
  sessions.delete(session.targetId);
  activeOffers.delete(session.targetId);
  refreshInterface();
}

function closeAllSessions() {
  Array.from(sessions.values()).forEach(closeSession);
}

function helloEnvelope() {
  return {
    type: "hello",
    senderId: localIdentity.id,
    senderName: localIdentity.name
  };
}

function sendTo(session, envelope) {
  if (!session.channel || session.channel.readyState !== "open") return false;
  try {
    session.channel.send(JSON.stringify(envelope));
    return true;
  } catch {
    return false;
  }
}

function broadcast(envelope, excludeTargetId) {
  let delivered = 0;
  sessions.forEach(function(session) {
    if (session.targetId !== excludeTargetId && sendTo(session, envelope)) delivered += 1;
  });
  return delivered;
}

function rememberMessage(messageId) {
  seenMessages.add(messageId);
  if (seenMessages.size > MAX_MESSAGE_CACHE) {
    const oldest = seenMessages.values().next().value;
    seenMessages.delete(oldest);
  }
}

function handleEnvelope(session, envelope) {
  if (!envelope || typeof envelope.type !== "string") return;

  if (envelope.type === "hello") {
    session.name = safeText(envelope.senderName, 24) || "未知节点";
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

  if (envelope.type === "pong") {
    const sentAt = Number(envelope.at);
    if (Number.isFinite(sentAt)) {
      session.latency = Math.max(0, Date.now() - sentAt);
      refreshInterface();
    }
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
    const targetId = randomId();
    const session = createSession(targetId, "initiator");
    bindChannel(session, session.connection.createDataChannel("meshtalk", { ordered: true }));
    const offer = await session.connection.createOffer();
    await session.connection.setLocalDescription(offer);
    await waitForIceGathering(session.connection);
    const payload = {
      v: PROTOCOL_VERSION,
      app: "meshtalk",
      group: true,
      targetId: targetId,
      identity: localIdentity,
      sdp: session.connection.localDescription.sdp,
      candidates: session.candidates
    };
    elements.offerOutput.value = await compressedJson(payload);
    activeOffers.set(targetId, session);
    appendMessage("system", null, "新邀请码已生成（目标节点 " + targetId.slice(0, 6) + "）。请发送给对应成员。");
  } catch (error) {
    appendMessage("error", null, "创建邀请码失败：" + error.message);
  }
});

elements.acceptOffer.addEventListener("click", async function() {
  try {
    const invitation = await decompressedJson(elements.offerInput.value);
    if (invitation.app !== "meshtalk" || !invitation.sdp || !invitation.targetId) {
      throw new Error("邀请码格式无效");
    }
    if (invitation.targetId === localIdentity?.id) throw new Error("不能连接自己");
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
    const payload = {
      v: PROTOCOL_VERSION,
      app: "meshtalk",
      group: true,
      targetId: invitation.targetId,
      identity: localIdentity,
      sdp: session.connection.localDescription.sdp,
      candidates: session.candidates
    };
    elements.answerOutput.value = await compressedJson(payload);
    appendMessage("system", null, "回复码已生成。请返回给邀请码创建者。");
  } catch (error) {
    appendMessage("error", null, "加入房间失败：" + error.message);
  }
});

elements.completeConnection.addEventListener("click", async function() {
  try {
    const reply = await decompressedJson(elements.answerInput.value);
    if (reply.app !== "meshtalk" || !reply.sdp || !reply.targetId) throw new Error("回复码格式无效");
    const session = activeOffers.get(reply.targetId);
    if (!session) throw new Error("找不到对应的邀请记录；请重新生成并交换邀请码");
    if (reply.identity) session.name = safeText(reply.identity.name, 24) || "未知节点";
    await session.connection.setRemoteDescription({ type: "answer", sdp: reply.sdp });
    for (const candidate of reply.candidates || []) {
      await session.connection.addIceCandidate(candidate).catch(function() {});
    }
    activeOffers.delete(reply.targetId);
    appendMessage("system", null, "回复码已应用，正在握手。");
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

elements.copyOffer.addEventListener("click", function() {
  copyText(elements.offerOutput, "最新邀请码");
});
elements.copyAnswer.addEventListener("click", function() {
  copyText(elements.answerOutput, "最新回复码");
});

elements.messageForm.addEventListener("submit", function(event) {
  event.preventDefault();
  const text = elements.messageInput.value.replace(/\s+$/u, "").trim();
  if (!text || connectedSessions().length === 0) return;
  const envelope = {
    type: "chat",
    messageId: randomId(),
    senderId: localIdentity.id,
    senderName: localIdentity.name,
    text: text
  };
  const delivered = broadcast(envelope, null);
  if (delivered === 0) return;
  appendMessage("self", localIdentity.name + "（我）", text);
  elements.messageInput.value = "";
  elements.messageInput.focus();
});

elements.disconnect.addEventListener("click", function() {
  broadcast({ type: "bye" }, null);
  closeAllSessions();
  activeOffers.clear();
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
startHeartbeat();
refreshInterface();
appendMessage("system", null, "欢迎来到 MeshTalk 群聊。可连续生成多条邀请码，分别邀请不同成员。");
