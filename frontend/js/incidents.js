
const API = "http://localhost:8080/api/incidents";

const form = document.getElementById("incident-form");
const message = document.getElementById("message");
const incidentList = document.getElementById("incident-list");

async function loadIncidents() {
    try {
        const response = await fetch(API, {
            method: "GET",
            credentials: "include"
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Unable to load incidents");
        }

        const incidents = Array.isArray(data.incidents)
            ? data.incidents : [];

        incidentList.replaceChildren();

        if (incidents.length === 0) {
            incidentList.textContent = "No incidents reported.";
            return;
        }


incidents.forEach(incident => {
    const card = document.createElement("div");

    const heading = document.createElement("h3");
    heading.textContent = incident.title;

    const description = document.createElement("p");
    description.textContent = incident.description;

    const details = document.createElement("p");
    details.textContent =
        `Category: ${incident.category} | Severity: ${incident.severity}`;

    const status = document.createElement("p");
    status.textContent = `Current Status: ${incident.status}`;

    const select = document.createElement("select");

    ["Open", "In Progress", "Resolved"].forEach(value => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = value;
        select.appendChild(option);
    });

    select.value = incident.status || "Open";

    const updateButton = document.createElement("button");
    updateButton.textContent = "Update Status";

    updateButton.addEventListener("click", async () => {
        try {
            const response = await fetch(`${API}/${incident.id}`, {
                method: "PATCH",
                credentials: "include",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    status: select.value
                })
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || "Update failed");
            }

            message.textContent = "Incident status updated!";
            await loadIncidents();

        } catch (error) {
            message.textContent = error.message;
        }
    });

    card.append(
        heading,
        description,
        details,
        status,
        select,
        updateButton
    );

    incidentList.appendChild(card);
});

    } catch (error) {
        incidentList.textContent = error.message;
    }
}

form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const incident = {
        title: document.getElementById("title").value.trim(),
        description: document.getElementById("description").value.trim(),
        category: document.getElementById("category").value.trim(),
        severity: document.getElementById("severity").value
    };

    try {
        const response = await fetch(API, {
            method: "POST",
            credentials: "include",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(incident)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Incident submission failed");
        }

        message.textContent = "Incident submitted successfully!";
        form.reset();
        loadIncidents();

    } catch (error) {
        message.textContent = error.message;
    }
});

document.getElementById("refresh-incidents")
    .addEventListener("click", loadIncidents);

loadIncidents();

async function deleteIncident(id) {
    if (!confirm("Are you sure you want to delete this incident?")) {
        return;
    }

    try {
        const response = await fetch(
            `http://localhost:8080/api/incidents/${id}`,
            {
                method: "DELETE",
                credentials: "include"
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Could not delete incident");
        }

        alert(data.message);

        await loadIncidents();

    } catch (error) {
        alert("Delete error: " + error.message);
    }
}