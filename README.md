# 🛡️ CyberPortal – Cybersecurity Management Portal

CyberPortal is a web-based cybersecurity management system that helps security analysts monitor network assets, scan open ports, manage vulnerabilities, track security incidents, and monitor threats through a centralized dashboard.

## 🚀 Features

- **Dashboard:** Overview of security activities and statistics.
- **Port Scanner:** Scan authorized IP addresses and detect open TCP ports.
- **Threat Intelligence:** Track IP addresses, domains, and threat classifications.
- **Vulnerability Management:** Manage CVEs, severity levels, and vulnerability status.
- **Incident Management:** Create, update, and track security incidents.
- **Asset Management:** Manage network assets and their details.
- **Security Logs:** Monitor and review security events.
- **Authentication:** Secure login and registration with bcrypt password hashing.
- **Settings:** Manage scan history and security-related data.

## 🧰 Technologies Used

- HTML, CSS, JavaScript
- Go (Golang)
- SQLite
- REST API
- bcrypt

## 📁 Project Structure

```text
cybersecurity-soc--analysis/
├── backend/
│   ├── main.go
│   ├── scanner.go
│   ├── go.mod
│   └── go.sum
├── frontend/
│   ├── HTML files
│   ├── css/style.css
│   └── js/JavaScript files
├── database/
└── README.md
```

## ⚙️ Installation

**1. Clone the repository**

```bash
https://github.com/durgaprasadkarri/cybersecurity-soc--analysis.git
```

**2. Navigate to the backend**

```bash
cd cybersecurity-soc--analysis/backend
```

**3. Install dependencies**

```bash
go mod tidy
```

**4. Run the backend**

```bash
go run .
```

Backend URL: `http://localhost:8080`

**5. Run the frontend**

Open the frontend using VS Code Live Server.

## 🔒 Security Notice

Use scanning features only on systems and networks you own or have permission to test. Do not publish passwords, API keys, or sensitive database information.

## 🔮 Future Enhancements

- AI-based threat detection
- Automated vulnerability assessment
- Advanced security analytics
- Security report generation

## 👨‍💻 Author

k.Durga prasad

**Project:** Cybersecurity Management Portal

