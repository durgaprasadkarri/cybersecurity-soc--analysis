
const SETTINGS_API = "http://localhost:8080/api/settings/";

async function clearPortalData(action) {
    const messages = document.getElementById("data-management-message");

const confirmations = {
    "clear-scan-history": "Are you sure you want to delete all scan history?",
    "clear-security-logs": "Are you sure you want to delete all security logs?",
    "reset-all-data": "WARNING: This will delete all portal records for every user. Continue?"
};
    if (!confirm(confirmations[action])) {
        return;
    }

    messages.textContent = "Processing...";

    try {
        const response = await fetch(SETTINGS_API + action, {
            method: "POST",
            credentials: "include"
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Operation failed");
        }

        messages.textContent = data.message || "Data cleared successfully.";
    } catch (error) {
        messages.textContent = "Error: " + error.message;
    }
}

document.getElementById("clear-scan-history")
    ?.addEventListener("click", () => {
        clearPortalData("clear-scan-history");
    });

document.getElementById("clear-security-logs")
    ?.addEventListener("click", () => {
        clearPortalData("clear-security-logs");
    });

document.getElementById("reset-all-data")
    ?.addEventListener("click", () => {
        clearPortalData("reset-all-data");
    });
