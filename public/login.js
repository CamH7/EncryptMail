// public/login.js
// Toggle password visibility
document.querySelectorAll(".toggle-pw").forEach((btn) => {
  btn.onclick = () => {
    const inp = document.getElementById(btn.dataset.target);
    inp.type = inp.type === "password" ? "text" : "password";
    btn.innerHTML =
      inp.type === "password"
        ? '<i class="fa fa-eye"></i>'
        : '<i class="fa fa-eye-slash"></i>';
  };
});

// Handle login
document.getElementById("btn").onclick = async () => {
  const username = document.getElementById("u").value.trim();
  const password = document.getElementById("p").value;
  const remember = document.getElementById("remember").checked;
  if (!username || !password) return alert("Fill in both fields");

  const res = await fetch("/api/login", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password, remember }),
  });

  if (!res.ok) {
    return alert((await res.json()).error);
  }

  sessionStorage.setItem("user", username);
  sessionStorage.setItem("pass", password);
  location.href = "/index.html";
};
