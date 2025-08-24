const API_KEY = process.env.OPENROUTER_API_KEY;
const API_URL = "https://openrouter.ai/api/v1/chat/completions";

let sessions = JSON.parse(localStorage.getItem("sessions")) || {};
let currentSessionId = null;

const chatBox = document.getElementById("chat-box");
const userInput = document.getElementById("user-input");
const sendBtn = document.getElementById("send-btn");
const sessionList = document.getElementById("session-list");
const newSessionBtn = document.getElementById("new-session-btn");

// Initialize
function init() {
  if (Object.keys(sessions).length === 0) {
    createNewSession();
  } else {
    const firstId = Object.keys(sessions)[0];
    loadSession(firstId);
  }
  renderSessionList();
}

function createNewSession() {
  const id = Date.now().toString();
  sessions[id] = { title: "New Chat", messages: [] };
  currentSessionId = id;
  saveSessions();
  renderSessionList();
  renderChat();
}

function loadSession(id) {
  currentSessionId = id;
  renderSessionList();
  renderChat();
}

function deleteSession(id) {
  delete sessions[id];
  if (Object.keys(sessions).length === 0) {
    createNewSession();
  } else {
    const firstId = Object.keys(sessions)[0];
    loadSession(firstId);
  }
  saveSessions();
  renderSessionList();
}

function renderSessionList() {
  sessionList.innerHTML = "";
  Object.entries(sessions).forEach(([id, session]) => {
    const div = document.createElement("div");
    div.className = `session-item ${id === currentSessionId ? "active" : ""}`;
    div.innerHTML = `
      <span>${session.title}</span>
      <span class="delete-btn" onclick="deleteSession('${id}')">🗑️</span>
    `;
    div.onclick = () => loadSession(id);
    sessionList.appendChild(div);
  });
}

function renderChat() {
  chatBox.innerHTML = "";
  sessions[currentSessionId].messages.forEach(msg => {
    const div = document.createElement("div");
    div.className = `message ${msg.role}`;
    div.textContent = msg.content;
    chatBox.appendChild(div);
  });
  chatBox.scrollTop = chatBox.scrollHeight;
}

async function sendMessage() {
  const text = userInput.value.trim();
  if (!text) return;

  sessions[currentSessionId].messages.push({ role: "user", content: text });

  if (sessions[currentSessionId].title === "New Chat") {
    sessions[currentSessionId].title = text.slice(0, 20) + "...";
  }

  renderChat();
  userInput.value = "";

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "openai/gpt-3.5-turbo", // or another OpenRouter-supported model
        messages: sessions[currentSessionId].messages,
      }),
    });

    const data = await response.json();
    const reply = data.choices[0].message.content;

    sessions[currentSessionId].messages.push({ role: "bot", content: reply });
    saveSessions();
    renderChat();
  } catch (err) {
    console.error("Error:", err);
  }
}

function saveSessions() {
  localStorage.setItem("sessions", JSON.stringify(sessions));
}

// Events
sendBtn.addEventListener("click", sendMessage);
userInput.addEventListener("keypress", e => {
  if (e.key === "Enter") sendMessage();
});
newSessionBtn.addEventListener("click", createNewSession);

init();
