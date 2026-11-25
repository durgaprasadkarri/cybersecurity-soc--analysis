
const MONITOR_API = "http://localhost:8080";

async function checkMonitorServer() {
    const serverElement = document.getElementById("monitor-server");
    const statusElement = document.getElementById("monitor-status");

    try {
        const response = await fetch(`${MONITOR_API}/api/health`);

        if (!response.ok) {
            throw new Error("Server unavailable");
        }

        serverElement.textContent = "ONLINE";
        statusElement.textContent = "SYSTEM ONLINE";

    } catch (error) {
        serverElement.textContent = "OFFLINE";
        statusElement.textContent = "CONNECTION FAILED";
    }
}

async function loadMonitorEvents() {
    const feed = document.getElementById("monitor-feed");
    const message = document.getElementById("monitor-message");

    try {
        const response = await fetch(
            `${MONITOR_API}/api/security-logs`,
            {
                method: "GET",
                credentials: "include"
            }
        );

        if (!response.ok) {
            throw new Error("Failed to fetch security logs");
        }

        const result = await response.json();

        // Support either an array or an object containing logs
        const logs = Array.isArray(result)
            ? result
            : result.logs || result.data || [];

        document.getElementById("monitor-events").textContent =
            logs.length;

        const criticalCount = logs.filter(log =>
            String(log.severity || log.level || "")
                .toLowerCase() === "critical"
        ).length;

        document.getElementById("monitor-critical").textContent =
            criticalCount;

        feed.innerHTML = "";

        if (logs.length === 0) {
            feed.innerHTML = `
                <tr>
                    <td colspan="5">No security events found.</td>
                </tr>
            `;

            message.textContent = "Monitoring active. No events recorded.";
            return;
        }

        // Display latest 50 events
        logs.slice(0, 50).forEach(log => {
            const row = document.createElement("tr");

            const values = [
                log.id ?? "-",
                log.event ?? log.action ?? log.event_type ?? "-",
                log.severity ?? log.level ?? "Unknown",
                log.details ?? log.description ?? "-",
                log.created_at ?? log.timestamp ?? log.time ?? "-"
            ];

            values.forEach((value, index) => {
                const cell = document.createElement("td");

                // Prevent log data from being interpreted as HTML
                cell.textContent = String(value);

                if (index === 2) {
                    cell.className =
                        String(value).toLowerCase();
                }

                row.appendChild(cell);
            });

            feed.appendChild(row);
        });

        message.textContent =
            `Monitoring active. Loaded ${logs.length} security events.`;

    } catch (error) {
        console.error("Monitoring error:", error);

        feed.innerHTML = `
            <tr>
                <td colspan="5">Unable to load security events.</td>
            </tr>
        `;

        message.textContent = "Failed to load monitoring feed.";
    }
}

async function refreshMonitoring() {
    await checkMonitorServer();
    await loadMonitorEvents();
}

document.addEventListener("DOMContentLoaded", () => {

    refreshMonitoring();

    // Automatic refresh every 5 seconds
    setInterval(refreshMonitoring, 5000);

    // Manual refresh
    document.getElementById("refresh-monitor")
        .addEventListener("click", refreshMonitoring);

});
