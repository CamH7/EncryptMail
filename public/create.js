// public/create.js
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

// Handle signup with key generation
document.getElementById("btn").onclick = async () => {
  const u = document.getElementById("u").value.trim();
  const p1 = document.getElementById("p1").value;
  const p2 = document.getElementById("p2").value;
  const remember = document.getElementById("remember").checked;
  if (!u || !p1) return alert("Fill in all fields");
  if (p1 !== p2) return alert("Passwords don't match");

  // Generate keypair
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
  const pub = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
  const priv = await window.crypto.subtle.exportKey(
    "pkcs8",
    keyPair.privateKey
  );
  const pubB64 = btoa(String.fromCharCode(...new Uint8Array(pub)));
  const privB64 = btoa(String.fromCharCode(...new Uint8Array(priv)));
  localStorage.setItem("publicKey", pubB64);
  localStorage.setItem("privateKey", privB64);

  // Create account
  const res = await fetch("/api/create", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: u, password: p1, publicKey: pubB64 }),
  });
  if (!res.ok) {
    return alert("Signup failed: " + (await res.json()).error);
  } else {
    alert("Account Created! Please log in!");
  }

  sessionStorage.setItem("user", u);
  sessionStorage.setItem("pass", p1);
  location.href = "/index.html";
};
