# EncryptMail
A full-stack minimalist webmail system using native browser RSA-OAEP encryption via Web Crypto API and an Express.js backend for secure message handling and storage

## Features

- 🔐 RSA-OAEP keypair generation (client-side)
- 🔒 End-to-end encryption (E2EE) using the Web Crypto API
- 🖥️ Express.js backend with RESTful API routes
- ✉️ Asymmetric dual-recipient encryption
- 📝 Draft saving with encryption
- 📬 Full Inbox, Sent, and Drafts tabs
- 🧠 LocalStorage/SessionStorage account memory
- 🔒 Password validation & account deletion
- 🧾 Audit logging and login rate limiting
- 💾 Lightweight file-based backend (JSON)

## Tech Stack

- Frontend: HTML, CSS, JS, Web Crypto API
- Backend: Node.js, Express, file-based storage

## Setup

### Clone the repository
git clone https://github.com/CamH7/EncryptMail.git
cd EncryptMail

### Install dependencies
npm install

### Create initial JSON files with default content
echo '{
  "users": [],
  "messages": []
}' > data.json

echo '{
  "drafts": []
}' > drafts.json

echo '{
  "accountCreations": [],
  "loginAttempts": [],
  "messagesSent": []
}' > audit.json

### Start the server
npm start

### Then open your browser to http://localhost:3000
