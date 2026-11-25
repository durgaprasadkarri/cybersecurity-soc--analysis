
const SCAN_API = "http://localhost:8080/api/scan";

const scanForm = document.getElementById("scan-form");
const jsonResponse = document.getElementById("json-response");
scanForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const message = document.getElementById("scan-message");
    const resultsTable = document.getElementById("scan-results");

    const scanButton = document.getElementById("scan-button");
    const targetCard = document.getElementById("scanned-target");
    const openPortCard = document.getElementById("open-port-count");
    const statusCard = document.getElementById("scan-status");

    const requestData = {
        target: document.getElementById("target").value.trim(),
        start_port: Number(document.getElementById("start-port").value),
        end_port: Number(document.getElementById("end-port").value)
    };

    // Validate port range
  if (
    !requestData.target ||
    !Number.isInteger(requestData.start_port) ||
    !Number.isInteger(requestData.end_port) ||
    requestData.start_port < 1 ||
    requestData.start_port > 65535 ||
    requestData.end_port < 1 ||
    requestData.end_port > 65535 ||
    requestData.start_port > requestData.end_port
) {
    message.textContent =
        "Enter a valid IP address and port range between 1 and 65535.";
    return;
}

    // Reset scan information
    message.textContent = "Scanning in progress...";
    resultsTable.replaceChildren();

    targetCard.textContent = requestData.target;
    openPortCard.textContent = "0";
    statusCard.textContent = "Scanning";

    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";

    try {
        const response = await fetch(SCAN_API, {
            method: "POST",
            credentials: "include",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(requestData)
        });

        const responseText = await response.text();

        let data;

        try {
            data = JSON.parse(responseText);
        } catch {
            throw new Error(
                "Backend returned a non-JSON response: " +
                responseText.substring(0, 200)
            );
        }

        if (!response.ok) {
            throw new Error(data.error || "Scan failed");
        }

        const openPorts = Array.isArray(data.open_ports)
            ? data.open_ports
            : [];
            // Get latest threat intelligence result
let threatData = null;

try {
    const threatResponse = await fetch(
        "http://localhost:8080/api/threat-intelligence/lookup",
        {
            method: "POST",
            credentials: "include",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                ip_address: requestData.target
            })
        }
    );

    if (threatResponse.ok) {
        threatData = await threatResponse.json();
    }
} catch (error) {
    console.error("Threat intelligence lookup failed:", error);
}

// Combine both responses
const combinedData = {
    port_scan: {
        total_found: data.total_found ?? openPorts.length,
        open_ports: openPorts
    },
    threat_intelligence: threatData || {
        status: "Unavailable",
        details: "Threat intelligence lookup failed."
    }
};

// Display combined JSON
let output = "";

output += "PORT SCAN RESULTS\n";
output += "-------------------------\n";
output += "Total Open Ports: " + combinedData.port_scan.total_found + "\n\n";

combinedData.port_scan.open_ports.forEach((port, index) => {
    output += "Port " + (index + 1) + "\n";
    output += "Port Number: " + port.port + "\n";
    output += "Protocol: " + port.protocol + "\n";
    output += "State: " + port.state + "\n";
    output += "Service: " + port.service + "\n";
    output += "Version: " + port.version + "\n\n";
});

output += "THREAT INTELLIGENCE\n";
output += "-------------------------\n";

const threat = combinedData.threat_intelligence;

output += "Status: " + (threat.status || "Completed") + "\n";
output += "IP Address: " + (threat.ip_address || "Not available") + "\n";
output += "Domain Name: " + (threat.domain_name || "Not available") + "\n";
output += "Classification: " + (threat.classification || "Not available") + "\n";
output += "Risk: " + (threat.risk || "Not available") + "\n";
output += "Details: " + (threat.details || "No details available");

jsonResponse.textContent = output;

        // Update dashboard cards
        targetCard.textContent = data.target || requestData.target;
        openPortCard.textContent = data.total_found ?? openPorts.length;
        statusCard.textContent = "Completed";

        // Display scan results
        if (openPorts.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 5;
            cell.textContent = "No open ports found.";

            row.appendChild(cell);
            resultsTable.appendChild(row);
        } else {
            openPorts.forEach((result) => {
                const row = document.createElement("tr");

                const values = [
                    result.port,
                    result.protocol,
                    result.state,
                    result.service,
                    result.version || "Not detected"
                ];

                values.forEach((value) => {
                    const cell = document.createElement("td");
                    cell.textContent = value;
                    row.appendChild(cell);
                });

                resultsTable.appendChild(row);
            });
        }

        message.textContent =
            `Scan completed! ${openPorts.length} open ports found on ${data.target}.`;

    } catch (error) {
        statusCard.textContent = "Failed";
        message.textContent = "Error: " + error.message;

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 5;
        cell.textContent = "Scan failed. Please check the backend.";

        row.appendChild(cell);
        resultsTable.appendChild(row);

    } finally {
        scanButton.disabled = false;
        scanButton.textContent = "Start Scan";
    }
});

