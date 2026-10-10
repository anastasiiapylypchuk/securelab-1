const result = document.querySelector("#result");
const profile = document.querySelector("#profile");
const registerResult = document.querySelector("#registerResult");
const createResult = document.querySelector("#createResult");

document.querySelector("#register").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const response = await fetch("/api/auth/register", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(Object.fromEntries(new FormData(form))) });
  form.elements.password.value = "";
  registerResult.textContent = `Register: ${response.status}`;
});

document.querySelector("#login").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const response = await fetch("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(Object.fromEntries(new FormData(form))) });
  form.elements.password.value = "";
  result.textContent = `Login: ${response.status}`;
});

document.querySelector("#me").addEventListener("click", async () => {
  const response = await fetch("/api/me");
  const type = response.headers.get("content-type") || "";
  if (response.ok && type.includes("application/json")) {
    const data = await response.json();
    profile.textContent = `${data.userName} (${data.displayName})`;
  } else {
    profile.textContent = "";
  }
  result.textContent = `Profile: ${response.status}`;
});

document.querySelector("#create").addEventListener("submit", async event => {
  event.preventDefault();
  const data = new FormData(event.currentTarget);
  const response = await fetch("/api/incidents", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      title: data.get("title"),
      description: data.get("description"),
      severity: data.get("severity"),
      occurredAtUtc: new Date(data.get("occurredAtUtc")).toISOString()
    }) });
  createResult.textContent = `Create: ${response.status}`;
});

document.querySelector("#logout").addEventListener("click", async () => {
  const response = await fetch("/api/auth/logout", { method: "POST" });
  profile.textContent = "";
  createResult.textContent = "";
  result.textContent = `Logout: ${response.status}`;
});