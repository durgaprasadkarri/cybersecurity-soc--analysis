
const AUTH_API = "http://localhost:8080/api";

async function authRequest(endpoint, body) {
    const response = await fetch(`${AUTH_API}${endpoint}`, {
        method: "POST",
        credentials: "include",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(body)
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
        throw new Error(data.error || "Authentication failed");
    }

    return data;
}

function showAuthMessage(message, color) {
    const element = document.getElementById("auth-message");

    if (!element) return;

    element.textContent = message;
    element.style.color = color;
}

// Check whether the user is logged in
async function checkLogin() {
    try {
        const response = await fetch(`${AUTH_API}/me`, {
            method: "GET",
            credentials: "include"
        });

        if (!response.ok) {
            window.location.href = "login.html";
            return false;
        }

        return true;

    } catch (error) {
        console.error("Login check failed:", error);
        window.location.href = "login.html";
        return false;
    }
}

// Registration
const registerForm = document.getElementById("register-form");

if (registerForm) {
    registerForm.addEventListener("submit", async event => {
        event.preventDefault();

        const user = {
            name: document.getElementById("name").value.trim(),
            email: document.getElementById("email").value.trim(),
            password: document.getElementById("password").value
        };

        try {
            const data = await authRequest("/register", user);

            showAuthMessage(data.message, "green");
            registerForm.reset();

            setTimeout(() => {
                window.location.href = "login.html";
            }, 1200);

        } catch (error) {
            showAuthMessage(error.message, "red");
        }
    });
}

// Login
const loginForm = document.getElementById("login-form");

if (loginForm) {
    loginForm.addEventListener("submit", async event => {
        event.preventDefault();

        const credentials = {
            email: document.getElementById("email").value.trim(),
            password: document.getElementById("password").value
        };

        try {
            const data = await authRequest("/login", credentials);

            showAuthMessage(data.message, "green");

            setTimeout(() => {
                window.location.href = "index.html";
            }, 500);

        } catch (error) {
            showAuthMessage(error.message, "red");
        }
    });
}

// Logout
const logoutButton = document.getElementById("logout-btn");

if (logoutButton) {
    logoutButton.addEventListener("click", async () => {
        logoutButton.disabled = true;
        logoutButton.textContent = "Logging out...";

        try {
            const response = await fetch(`${AUTH_API}/logout`, {
                method: "POST",
                credentials: "include"
            });

            if (!response.ok) {
                throw new Error("Logout failed");
            }

            window.location.href = "login.html";

        } catch (error) {
            console.error("Logout error:", error);
            alert("Unable to logout. Please try again.");

            logoutButton.disabled = false;
            logoutButton.textContent = "Logout";
        }
    });
}
