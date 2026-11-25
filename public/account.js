const logoutBtn = document.getElementById("logoutBtn");

logoutBtn.addEventListener("click", async () => {
  logoutBtn.disabled = true;
  logoutBtn.textContent = "Logging out...";

  try {
    const response = await fetch("/api/auth/logout", { method: "POST" });
    if (!response.ok) throw new Error("Logout request failed.");
    window.location.assign("/login");
  } catch {
    window.alert("Could not log out. Please try again.");
    logoutBtn.disabled = false;
    logoutBtn.textContent = "Log out";
  }
});
