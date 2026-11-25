
const API = "http://localhost:8080";

async function loadDashboardStats() {
    try {
        const response = await fetch(`${API}/api/dashboard/stats`, {
            method: "GET",
            credentials: "include"
        });

        if (!response.ok) {
            throw new Error("Unable to load dashboard statistics");
        }

        const stats = await response.json();

        const elements = {
            "total-assets": stats.total_assets,
            "total-vulnerabilities": stats.total_vulnerabilities,
            "open-incidents": stats.open_incidents,
            "total-security-logs": stats.total_security_logs
        };

        for (const [id, value] of Object.entries(elements)) {
            const element = document.getElementById(id);

            if (element) {
                element.textContent = value ?? 0;
            } else {
                console.warn(`HTML element not found: ${id}`);
            }
        }

    } catch (error) {
        console.error("Dashboard error:", error);
    }
}

document.addEventListener("DOMContentLoaded", loadDashboardStats);
