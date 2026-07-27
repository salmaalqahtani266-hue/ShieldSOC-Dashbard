document.addEventListener("DOMContentLoaded", () => {
    const loginForm = document.getElementById("loginForm");
    const usernameInput = document.getElementById("username");
    const passwordInput = document.getElementById("password");
    const loginButton = document.getElementById("loginButton");
    const loginMessage = document.getElementById("loginMessage");
    const togglePassword = document.getElementById("togglePassword");
    
const forgotPasswordButton =
    document.getElementById("forgotPasswordButton");

const forgotPasswordModal =
    document.getElementById("forgotPasswordModal");

const closeForgotModal =
    document.getElementById("closeForgotModal");

const forgotPasswordForm =
    document.getElementById("forgotPasswordForm");

const recoveryUsername =
    document.getElementById("recoveryUsername");

const forgotPasswordMessage =
    document.getElementById("forgotPasswordMessage");

const sendResetButton =
    document.getElementById("sendResetButton");

    function showMessage(message, type = "error") {
        loginMessage.hidden = false;
        loginMessage.textContent = message;
        loginMessage.className = `login-message ${type}`;
    }

    function hideMessage() {
        loginMessage.hidden = true;
        loginMessage.textContent = "";
        loginMessage.className = "login-message";
    }

    togglePassword.addEventListener("click", () => {
        const isHidden = passwordInput.type === "password";

        passwordInput.type = isHidden ? "text" : "password";
        togglePassword.textContent = isHidden ? "Hide" : "Show";
        togglePassword.setAttribute(
            "aria-label",
            isHidden ? "Hide password" : "Show password"
        );
    });
function showForgotMessage(message, type = "success") {
    forgotPasswordMessage.hidden = false;
    forgotPasswordMessage.textContent = message;
    forgotPasswordMessage.className =
        `login-message ${type}`;
}

function closeRecoveryModal() {
    forgotPasswordModal.hidden = true;
    forgotPasswordForm.reset();
    forgotPasswordMessage.hidden = true;
}

forgotPasswordButton.addEventListener("click", () => {
    forgotPasswordModal.hidden = false;
    recoveryUsername.focus();
});

closeForgotModal.addEventListener("click", closeRecoveryModal);

forgotPasswordModal.addEventListener("click", (event) => {
    if (event.target === forgotPasswordModal) {
        closeRecoveryModal();
    }
});

forgotPasswordForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const username = recoveryUsername.value.trim();

    if (!username) {
        showForgotMessage(
            "Please enter your username.",
            "error"
        );
        return;
    }

    sendResetButton.disabled = true;
    sendResetButton.textContent = "Processing...";

    try {
        const response = await fetch("/api/forgot-password", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ username })
        });

        const result = await response.json();

        showForgotMessage(result.message, "success");

    } catch (error) {
        console.error("Password recovery error:", error);

        showForgotMessage(
            "Unable to process the request. Please try again.",
            "error"
        );
    } finally {
        sendResetButton.disabled = false;
        sendResetButton.textContent =
            "Send Reset Instructions";
    }
});
    loginForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        hideMessage();

        const username = usernameInput.value.trim();
        const password = passwordInput.value;

        if (!username || !password) {
            showMessage("Please enter your username and password.");
            return;
        }

        loginButton.disabled = true;
        loginButton.textContent = "Signing In...";

        try {
            const response = await fetch("/api/login", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    username,
                    password
                })
            });

            const result = await response.json();

            if (!response.ok || !result.success) {
                showMessage(
                    result.message || "Invalid username or password."
                );
                return;
            }

            showMessage("Login successful. Redirecting...", "success");

            setTimeout(() => {
                window.location.href = "/";
            }, 600);

        } catch (error) {
            console.error("Login error:", error);

            showMessage(
                "Unable to connect to ShieldSOC. Please try again."
            );
        } finally {
            loginButton.disabled = false;
            loginButton.textContent = "Sign In";
        }
    });
});