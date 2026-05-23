(function () {
  const form = document.getElementById("test-form");
  const promptEl = document.getElementById("test-prompt");
  const uploadEl = document.getElementById("test-upload");
  const uploadNameEl = document.getElementById("test-upload-name");
  const submitBtn = document.getElementById("test-submit");
  const chatLog = document.getElementById("test-chat-log");
  const statusEl = document.getElementById("test-status");

  if (!form || !promptEl || !submitBtn || !chatLog) {
    return;
  }

  function setStatus(text) {
    if (!statusEl) return;
    if (!text) {
      statusEl.hidden = true;
      statusEl.textContent = "";
      statusEl.classList.remove("is-active");
      return;
    }
    statusEl.hidden = false;
    statusEl.textContent = text;
    statusEl.classList.add("is-active");
  }

  function appendAssistantMessage(text) {
    const message = document.createElement("div");
    message.className = "chat-message is-assistant";
    message.dataset.testid = "assistant-message";

    const bubble = document.createElement("div");
    bubble.className = "chat-bubble";

    const paragraph = document.createElement("p");
    paragraph.textContent = text;

    bubble.appendChild(paragraph);
    message.appendChild(bubble);
    chatLog.appendChild(message);
    message.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }

  function selectedFile() {
    if (!uploadEl || !uploadEl.files || !uploadEl.files.length) {
      return null;
    }
    return uploadEl.files[0];
  }

  function syncUploadHint() {
    if (!uploadNameEl) return;
    const file = selectedFile();
    if (!file) {
      uploadNameEl.hidden = true;
      uploadNameEl.textContent = "";
      return;
    }
    uploadNameEl.hidden = false;
    uploadNameEl.textContent = "Attached: " + file.name + " (" + file.type + ")";
  }

  function syncSubmitState() {
    const hasPrompt = promptEl.value.trim().length > 0;
    const hasFile = !!selectedFile();
    submitBtn.disabled = !(hasPrompt || hasFile);
  }

  promptEl.addEventListener("input", syncSubmitState);
  if (uploadEl) {
    uploadEl.addEventListener("change", function () {
      syncUploadHint();
      syncSubmitState();
    });
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    const text = promptEl.value.trim();
    const file = selectedFile();
    if (!text && !file) return;

    submitBtn.disabled = true;
    setStatus(file ? "Uploading and analyzing with Gemini…" : "Generating response…");

    const requestInit = { method: "POST" };
    if (file) {
      const formData = new FormData();
      formData.append("prompt", text || "Please analyze the attached file.");
      formData.append("file", file, file.name);
      requestInit.body = formData;
    } else {
      requestInit.headers = { "Content-Type": "application/json" };
      requestInit.body = JSON.stringify({ prompt: text });
    }

    fetch("/api/chat", requestInit)
      .then(function (response) {
        return response.json().then(function (body) {
          return { ok: response.ok, status: response.status, body: body };
        });
      })
      .then(function (result) {
        if (!result.ok) {
          const detail = result.body && result.body.detail;
          const message =
            typeof detail === "string"
              ? detail
              : "Request failed (" + result.status + ")";
          throw new Error(message);
        }
        appendAssistantMessage(result.body.response);
        promptEl.value = "";
        if (uploadEl) {
          uploadEl.value = "";
          syncUploadHint();
        }
      })
      .catch(function (err) {
        appendAssistantMessage("Error: " + (err && err.message ? err.message : "request failed"));
      })
      .finally(function () {
        setStatus("");
        syncSubmitState();
      });
  });
})();
