const output = document.querySelector("#output");
const statusBox = document.querySelector("#status");

const fakeArchiveMarker = ["GCW", "client", "side", "bait"].join("{") + "}";

function print(value) {
  output.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

async function refreshMe() {
  const res = await fetch("/api/me");
  const body = await res.json();
  statusBox.textContent = body.user ? `visitor orbit: ${body.user.sub}` : "visitor orbit: none";
}

document.querySelector("#loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const res = await fetch("/api/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ handle: form.get("handle") })
  });
  print(await res.json());
  await refreshMe();
});

document.querySelector("#inspectForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = new FormData(event.currentTarget).get("url");
  const res = await fetch(`/api/inspector?url=${encodeURIComponent(url)}`);
  print(await res.json());
});

document.querySelector("#searchForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const q = new FormData(event.currentTarget).get("q");
  const res = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
  print(await res.json());
});

void fakeArchiveMarker;
refreshMe();
const output = document.querySelector("#output");
const statusBox = document.querySelector("#status");

const fakeArchiveMarker = ["GCW", "client", "side", "bait"].join("{") + "}";

function print(value) {
  output.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

async function refreshMe() {
  const res = await fetch("/api/me");
  const body = await res.json();
  statusBox.textContent = body.user ? `visitor orbit: ${body.user.sub}` : "visitor orbit: none";
}

document.querySelector("#loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const res = await fetch("/api/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ handle: form.get("handle") })
  });
  print(await res.json());
  await refreshMe();
});

document.querySelector("#inspectForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = new FormData(event.currentTarget).get("url");
  const res = await fetch(`/api/inspector?url=${encodeURIComponent(url)}`);
  print(await res.json());
});

document.querySelector("#searchForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const q = new FormData(event.currentTarget).get("q");
  const res = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
  print(await res.json());
});

void fakeArchiveMarker;
refreshMe();
