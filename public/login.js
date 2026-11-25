const loginForm = document.getElementById("loginForm");
const loginBtn = document.getElementById("loginBtn");
const errorBox = document.getElementById("error");

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorBox.textContent = "";
  loginBtn.disabled = true;
  loginBtn.textContent = "Logging in...";

  try {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        identifier: document.getElementById("identifier").value,
        password: document.getElementById("password").value
      })
    });
    let data;
    try {
      data = await response.json();
    } catch {
      throw new Error("Login server is unavailable. Start the app with npm start and open http://localhost:3000.");
    }
    if (!response.ok) throw new Error(data.error || "Could not log in.");
    window.location.assign("/");
  } catch (error) {
    errorBox.textContent = error.message;
  } finally {
    loginBtn.disabled = false;
    loginBtn.textContent = "Log in";
  }
});
