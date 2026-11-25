
// API_BASE and apiRequest are provided by app.js

document.addEventListener("DOMContentLoaded", async () => {
    const form = document.getElementById("vulnerability-form");

    if (!form) return;

    try {
        await loadAssetOptions();
        await loadVulnerabilities();
    } catch (error) {
        showMessage(error.message, "red");
    }

    form.addEventListener("submit", addVulnerability);
});

// Display messages
function showMessage(message, color) {
    const element = document.getElementById("vulnerability-message");

    if (!element) return;

    element.textContent = message;
    element.style.color = color;
}

// Load assets into the dropdown
async function loadAssetOptions() {
    const select = document.getElementById("affected-asset");
    const data = await apiRequest("/assets");

    select.replaceChildren();

    const firstOption = document.createElement("option");
    firstOption.value = "";
    firstOption.textContent = "Select affected asset";
    select.appendChild(firstOption);

    data.assets.forEach(asset => {
        const option = document.createElement("option");

        option.value = asset.id;
        option.textContent = `${asset.hostname} (${asset.ip})`;

        select.appendChild(option);
    });
}

// Add vulnerability
async function addVulnerability(event) {
    event.preventDefault();

    const vulnerability = {
        cve_id: document.getElementById("cve-id").value.trim(),
        title: document.getElementById("vuln-title").value.trim(),
        asset_id: Number(document.getElementById("affected-asset").value),
        severity: document.getElementById("severity").value,
        cvss: Number(document.getElementById("cvss").value),
        description: document.getElementById("description").value.trim()
    };

    try {
        await apiRequest("/vulnerabilities", {
            method: "POST",
            body: JSON.stringify(vulnerability)
        });

        showMessage("Vulnerability added successfully!", "green");

        document.getElementById("vulnerability-form").reset();

        await loadVulnerabilities();
    } catch (error) {
        showMessage(error.message, "red");
    }
}

// Load vulnerabilities
async function loadVulnerabilities() {
    const data = await apiRequest("/vulnerabilities");

    const table = document.getElementById("vulnerability-table");

    if (!table) return;

    table.replaceChildren();

    const counts = {
        Critical: 0,
        High: 0,
        Resolved: 0
    };

    data.vulnerabilities.forEach(vulnerability => {
        if (vulnerability.severity === "Critical") counts.Critical++;
        if (vulnerability.severity === "High") counts.High++;
        if (vulnerability.status === "Resolved") counts.Resolved++;

        const row = document.createElement("tr");

        const values = [
            vulnerability.id,
            vulnerability.cve_id || "N/A",
            vulnerability.title,
            vulnerability.asset_id,
            vulnerability.severity,
            vulnerability.cvss,
            vulnerability.status
        ];

        values.forEach(value => {
            const cell = document.createElement("td");
            cell.textContent = value;
            row.appendChild(cell);
        });

        // Status update
        const actionCell = document.createElement("td");

        const statusSelect = document.createElement("select");

        ["Open", "In Progress", "Resolved"].forEach(status => {
            const option = document.createElement("option");
            option.value = status;
            option.textContent = status;
            statusSelect.appendChild(option);
        });

        statusSelect.value = vulnerability.status;

        statusSelect.addEventListener("change", async () => {
            try {
                await apiRequest(
                    `/vulnerabilities/${vulnerability.id}/status`,
                    {
                        method: "PATCH",
                        body: JSON.stringify({
                            status: statusSelect.value
                        })
                    }
                );

                await loadVulnerabilities();
            } catch (error) {
                alert(error.message);
            }
        });

        // Delete vulnerability
        const deleteButton = document.createElement("button");
        deleteButton.textContent = "Delete";

        deleteButton.addEventListener("click", async () => {
            if (!confirm("Delete this vulnerability?")) return;

            try {
                await apiRequest(
                `/vulnerabilities?id=${vulnerability.id}`,
                {
                    method: "DELETE"
                }
);

                await loadVulnerabilities();
            } catch (error) {
                alert(error.message);
            }
        });

        actionCell.append(statusSelect, deleteButton);
        row.appendChild(actionCell);

        table.appendChild(row);
    });

    document.getElementById("total-findings").textContent = data.total;
    document.getElementById("critical-count").textContent = counts.Critical;
    document.getElementById("high-count").textContent = counts.High;
    document.getElementById("resolved-count").textContent = counts.Resolved;
}
