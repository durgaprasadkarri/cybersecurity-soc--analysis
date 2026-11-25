
const LOGS_API = "http://localhost:8080/api/security-logs";

async function loadSecurityLogs() {
    const message = document.getElementById("log-message");
    const tableBody = document.getElementById("security-logs-body");

    if (!message || !tableBody) {
        console.error("Security logs HTML elements not found.");
        return;
    }

    message.textContent = "Loading security logs...";
    tableBody.replaceChildren();

    try {
        const response = await fetch(LOGS_API, {
            method: "GET",
            credentials: "include"
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Unable to load logs");
        }

        const logs = Array.isArray(data.logs) ? data.logs : [];

        if (logs.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 7;
            cell.textContent = "No security logs available yet.";

            row.appendChild(cell);
            tableBody.appendChild(row);

            message.textContent = "No security logs available.";
            return;
        }

        logs.forEach(log => {
            const row = document.createElement("tr");

            const values = [
                log.id,
                log.username,
                log.event_type,
                log.description,
                log.ip_address || "IP not recorded",
                log.status,
                log.created_at
            ];

            values.forEach(value => {
                const cell = document.createElement("td");
                cell.textContent = value ?? "-";
                row.appendChild(cell);
            });

            tableBody.appendChild(row);
        });

        message.textContent =
            `Showing ${logs.length} security logs.`;

    } catch (error) {
        message.textContent = "Error: " + error.message;
        console.error("Security logs error:", error);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    loadSecurityLogs();

    document.getElementById("refresh-logs")
        ?.addEventListener("click", loadSecurityLogs);
});
