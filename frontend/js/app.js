
const API_BASE = "http://localhost:8080/api";

// Common API request function
async function apiRequest(endpoint, options = {}) {
    const response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        credentials: "include",
        headers: {
            "Content-Type": "application/json",
            ...options.headers
        }
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
        throw new Error(data.error || "Request failed");
    }

    return data;
}

// Check backend connection
async function checkServer() {
    const status = document.getElementById("server-status");

    if (!status) return;

    try {
        const data = await apiRequest("/health");

        status.textContent = data.message || "Backend online";
        status.style.color = "green";
    } catch (error) {
        status.textContent = "Backend offline: " + error.message;
        status.style.color = "red";
    }
}

// Check logged-in user
async function checkAuthentication() {
    const userElement = document.getElementById("current-user");

    try {
        const data = await apiRequest("/me");

        if (userElement) {
            userElement.textContent =
                `${data.user.name} | ${data.user.role}`;
        }

        return true;
    } catch (error) {
        window.location.href = "login.html";
        return false;
    }
}

// Logout
async function logout() {
    try {
        await apiRequest("/logout", {
            method: "POST"
        });
    } catch (error) {
        console.error("Logout error:", error);
    }

    window.location.href = "login.html";
}

// Load assets
async function loadAssets() {
    const table = document.getElementById("asset-table-body");

    if (!table) return;

    try {
        const data = await apiRequest("/assets");

        table.replaceChildren();

        document.getElementById("total-assets").textContent =
            data.total;

        for (const asset of data.assets) {
            const row = document.createElement("tr");

            const values = [
                asset.id,
                asset.hostname,
                asset.ip,
                asset.type
            ];

            values.forEach(value => {
                const cell = document.createElement("td");
                cell.textContent = value;
                row.appendChild(cell);
            });

            const actionCell = document.createElement("td");
            const deleteButton = document.createElement("button");

            deleteButton.textContent = "Delete";

            deleteButton.addEventListener("click", async () => {
                if (!confirm("Delete this asset?")) return;

                try {
                    await apiRequest(`/assets?id=${asset.id}`, {
                        method: "DELETE"
                    });

                    loadAssets();
                } catch (error) {
                    alert(error.message);
                }
            });

            actionCell.appendChild(deleteButton);
            row.appendChild(actionCell);
            table.appendChild(row);
        }
    } catch (error) {
        console.error("Asset loading error:", error);
    }
}

// Add asset
async function addAsset(event) {
    event.preventDefault();

    const message = document.getElementById("asset-message");

    const asset = {
        hostname: document.getElementById("hostname").value.trim(),
        ip: document.getElementById("ip-address").value.trim(),
        type: document.getElementById("asset-type").value
    };

    try {
        await apiRequest("/assets", {
            method: "POST",
            body: JSON.stringify(asset)
        });

        message.textContent = "Asset added successfully!";
        message.style.color = "green";

        document.getElementById("asset-form").reset();

        await loadAssets();
    } catch (error) {
        message.textContent = error.message;
        message.style.color = "red";
    }
}

// Dashboard initialization
document.addEventListener("DOMContentLoaded", async () => {
    const isAuthenticated = await checkAuthentication();

    if (!isAuthenticated) return;

    const assetForm = document.getElementById("asset-form");
    const logoutButton = document.getElementById("logout-btn");
    const checkButton = document.getElementById("check-server");

    if (assetForm) {
        assetForm.addEventListener("submit", addAsset);
    }

    if (logoutButton) {
        logoutButton.addEventListener("click", logout);
    }

    if (checkButton) {
        checkButton.addEventListener("click", checkServer);
    }

    await Promise.all([
        loadAssets(),
        checkServer(),
        loadVulnerabilityCount()
    ]);
});

// Get vulnerability count for dashboard
async function loadVulnerabilityCount() {
    const element = document.getElementById("total-vulnerabilities");

    if (!element) return;

    try {
        const data = await apiRequest("/vulnerabilities");
        element.textContent = data.total;
    } catch (error) {
        console.error(error);
    }
}


document.addEventListener("DOMContentLoaded", () => {
    const currentPage = window.location.pathname.split("/").pop();

    document.querySelectorAll(".sidebar nav a").forEach(link => {
        const linkPage = link.getAttribute("href");

        if (linkPage === currentPage) {
            link.classList.add("active");
        } else {
            link.classList.remove("active");
        }
    });
});

