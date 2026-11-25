
const THREAT_API = "http://localhost:8080";

let investigations = 0;
let suspiciousCount = 0;
let safeCount = 0;

document.getElementById("result-ip").textContent =
    data.ip_address || ip;

document.getElementById("result-domain").textContent =
    data.domain_name || "No hostname found";
    
function isValidIPv4(ip) {
    const parts = ip.trim().split(".");

    if (parts.length !== 4) return false;

    return parts.every(part => {
        if (!/^\d{1,3}$/.test(part)) return false;

        const number = Number(part);

        return number >= 0 && number <= 255;
    });
}

function updateThreatCounters() {
    document.getElementById("ips-checked").textContent =
        investigations;

    document.getElementById("suspicious-ips").textContent =
        suspiciousCount;

    document.getElementById("safe-ips").textContent =
        safeCount;
}

function addHistory(ip, classification, risk) {
    const history = document.getElementById("ip-history");

    if (investigations === 1) {
        history.innerHTML = "";
    }

    const row = document.createElement("tr");

    [ip, classification, risk, new Date().toLocaleString()]
        .forEach(value => {
            const cell = document.createElement("td");
            cell.textContent = value;
            row.appendChild(cell);
        });

    history.prepend(row);
}

async function investigateIP(ip) {
    const message = document.getElementById("lookup-message");
    const button = document.getElementById("lookup-button");
    const result = document.getElementById("ip-result");

    button.disabled = true;
    button.textContent = "Investigating...";
    message.textContent = "Contacting threat intelligence service...";
    result.hidden = true;

    try {
        const response = await fetch(
            `${THREAT_API}/api/threat-intelligence/lookup`,
            {
                method: "POST",
                credentials: "include",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    ip_address: ip
                })
            }
        );

        const responseText = await response.text();

console.log("Backend HTTP status:", response.status);
console.log("Backend response:", responseText);

let data;

try {
    data = JSON.parse(responseText);
} catch (error) {
    throw new Error(
        "Backend returned invalid JSON. Check browser console."
    );
}

        if (!response.ok) {
            throw new Error(data.error || "Investigation failed");
        }

        // Expected backend response:
        // classification, risk, details

        if (!data.classification || !data.risk) {
            throw new Error("Invalid response from threat intelligence API");
        }

        investigations++;

        const classification = String(data.classification);
        const risk = String(data.risk);

        if (
            ["suspicious", "malicious"].includes(
                classification.toLowerCase()
            )
        ) {
            suspiciousCount++;
        } else if (classification.toLowerCase() === "safe") {
            safeCount++;
        }

        document.getElementById("result-ip").textContent = ip;
        document.getElementById("result-classification").textContent =
            classification;

        document.getElementById("result-risk").textContent = risk;

        document.getElementById("result-details").textContent =
            data.details || "No additional details provided.";

        result.hidden = false;

        addHistory(ip, classification, risk);
        updateThreatCounters();

        message.textContent = "Investigation completed.";
        document.getElementById("threat-status").textContent = "COMPLETED";
        document.getElementById("intel-status").textContent = "ACTIVE";

    } catch (error) {
        console.error("Threat intelligence error:", error);

        message.textContent = error.message;
        document.getElementById("threat-status").textContent = "ERROR";

    } finally {
        button.disabled = false;
        button.textContent = "Investigate IP";
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("ip-lookup-form");

    form.addEventListener("submit", event => {
        event.preventDefault();

        const ip = document.getElementById("ip-address")
            .value.trim();

        if (!isValidIPv4(ip)) {
            document.getElementById("lookup-message").textContent =
                "Enter a valid IPv4 address.";

            return;
        }

        investigateIP(ip);
    });
});
