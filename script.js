// ==========================================
// ShieldSOC Dashboard - Database Integration
// ==========================================

const API = {
    dashboard: "/api/dashboard",
    alerts: "/api/alerts",
    severity: "/api/severity",
    suspiciousIps: "/api/suspicious-ips",
    logs: "/api/logs",
    incidents: "/api/incidents"
};


// ==========================================
// أدوات مساعدة
// ==========================================

async function fetchJson(url) {
    const response = await fetch(url);

    if (!response.ok) {
        throw new Error(
            `Request failed: ${response.status}`
        );
    }

    return response.json();
}


function escapeHtml(value) {
    const element = document.createElement("div");
    element.textContent = value ?? "";
    return element.innerHTML;
}


function formatNumber(value) {
    return Number(value || 0).toLocaleString();
}


function formatDateTime(value) {
    if (!value) {
        return "Unknown";
    }

    const date = new Date(value.replace(" ", "T"));

    if (Number.isNaN(date.getTime())) {
        return value;
    }

    return date.toLocaleString();
}


function getTimeAgo(value) {
    if (!value) {
        return "Unknown";
    }

    const date = new Date(value.replace(" ", "T"));
    const now = new Date();

    if (Number.isNaN(date.getTime())) {
        return value;
    }

    const difference =
        Math.floor((now - date) / 1000);

    if (difference < 60) {
        return "Just now";
    }

    const minutes = Math.floor(difference / 60);

    if (minutes < 60) {
        return `${minutes} min ago`;
    }

    const hours = Math.floor(minutes / 60);

    if (hours < 24) {
        return `${hours} hr ago`;
    }

    const days = Math.floor(hours / 24);

    return `${days} day ago`;
}


function severityClass(severity) {
    const value = String(severity || "")
        .toLowerCase();

    if (
        value === "critical" ||
        value === "high" ||
        value === "medium" ||
        value === "low"
    ) {
        return value;
    }

    return "low";
}


function statusClass(status) {
    const value = String(status || "")
        .toLowerCase();

    if (
        value === "resolved" ||
        value === "contained" ||
        value === "blocked" ||
        value === "normal"
    ) {
        return "safe";
    }

    if (
        value === "new" ||
        value === "open" ||
        value === "alert"
    ) {
        return "danger";
    }

    return "warning";
}


// ==========================================
// بطاقات الإحصائيات
// ==========================================

async function loadDashboardSummary() {
    const data = await fetchJson(API.dashboard);

    document.getElementById("totalLogs").textContent =
        formatNumber(data.total_logs);

    document.getElementById(
        "criticalAlerts"
    ).textContent =
        formatNumber(data.critical_alerts);

    document.getElementById(
        "blockedIps"
    ).textContent =
        formatNumber(data.blocked_ips);

    document.getElementById(
        "activeIncidents"
    ).textContent =
        formatNumber(data.active_incidents);
}


// ==========================================
// التنبيهات الأمنية
// ==========================================

async function loadAlerts() {
    const alerts = await fetchJson(API.alerts);
    const container =
        document.querySelector(".alerts-table");

    if (!container) {
        return;
    }

    if (!alerts.length) {
        container.innerHTML = `
            <p class="empty-state">
                No security alerts found.
            </p>
        `;
        return;
    }

    container.innerHTML = alerts
        .slice(0, 4)
        .map((alert) => {
            const severity =
                escapeHtml(alert.severity);

            return `
                <div class="alert-row">
                    <span
                        class="severity-badge
                        ${severityClass(alert.severity)}"
                    >
                        ${severity}
                    </span>

                    <div class="alert-details">
                        <strong>
                            ${escapeHtml(
                                alert.alert_title
                            )}
                        </strong>

                        <p>
                            Source IP:
                            ${escapeHtml(
                                alert.source_ip || "Unknown"
                            )}
                        </p>
                    </div>

                    <div class="alert-source">
                        <span>
                            ${escapeHtml(
                                alert.environment
                            )}
                        </span>

                        <small>
                            ${escapeHtml(
                                alert.source
                            )}
                        </small>
                    </div>

                    <time title="${formatDateTime(
                        alert.detected_at
                    )}">
                        ${getTimeAgo(
                            alert.detected_at
                        )}
                    </time>
                </div>
            `;
        })
        .join("");
}


// ==========================================
// توزيع الخطورة
// ==========================================

async function loadSeverityDistribution() {
    const data = await fetchJson(API.severity);

    const levels = [
        {
            name: "Critical",
            selector: ".critical-bar"
        },
        {
            name: "High",
            selector: ".high-bar"
        },
        {
            name: "Medium",
            selector: ".medium-bar"
        },
        {
            name: "Low",
            selector: ".low-bar"
        }
    ];

    const total = levels.reduce(
        (sum, level) =>
            sum + Number(data[level.name] || 0),
        0
    );

    levels.forEach((level) => {
        const bar =
            document.querySelector(level.selector);

        if (!bar) {
            return;
        }

        const value =
            Number(data[level.name] || 0);

        const percentage =
            total > 0
                ? Math.round(
                    (value / total) * 100
                )
                : 0;

        bar.style.width =
            `${Math.max(percentage, 4)}%`;

        const item =
            bar.closest(".severity-item");

        const number =
            item?.querySelector("strong");

        if (number) {
            number.textContent = value;
        }
    });

    const summaryValues =
        document.querySelectorAll(
            ".threat-summary strong"
        );

    if (summaryValues.length >= 1) {
        summaryValues[0].textContent =
            formatNumber(total);
    }
}


// ==========================================
// عناوين IP المشبوهة
// ==========================================

async function loadSuspiciousIps() {
    const ips =
        await fetchJson(API.suspiciousIps);

    const container =
        document.querySelector(".ip-list");

    if (!container) {
        return;
    }

    if (!ips.length) {
        container.innerHTML = `
            <p class="empty-state">
                No suspicious IP addresses found.
            </p>
        `;
        return;
    }

    container.innerHTML = ips
        .slice(0, 4)
        .map((ip) => {
            const country =
                ip.country || "Unknown";

            const countryCode =
                country
                    .slice(0, 2)
                    .toUpperCase();

            return `
                <div class="ip-row">
                    <div class="ip-main">
                        <span class="country-code">
                            ${escapeHtml(countryCode)}
                        </span>

                        <div>
                            <strong>
                                ${escapeHtml(
                                    ip.ip_address
                                )}
                            </strong>

                            <p>
                                ${escapeHtml(country)}
                            </p>
                        </div>
                    </div>

                    <span class="event-count">
                        ${formatNumber(
                            ip.event_count
                        )}
                        Events
                    </span>
                </div>
            `;
        })
        .join("");
}


// ==========================================
// السجلات الأمنية
// ==========================================

async function loadLogs() {
    const logs = await fetchJson(API.logs);
    const container =
        document.querySelector(".logs-table");

    if (!container) {
        return;
    }

    const header = `
        <div class="log-row log-header">
            <span>Time</span>
            <span>Source</span>
            <span>Event</span>
            <span>Status</span>
        </div>
    `;

    if (!logs.length) {
        container.innerHTML =
            header +
            `
                <p class="empty-state">
                    No security logs found.
                </p>
            `;
        return;
    }

    const rows = logs
        .slice(0, 6)
        .map((log) => {
            const eventTime =
                log.event_time
                    ? log.event_time
                        .split(" ")[1]
                    : "--:--:--";

            return `
                <div class="log-row" data-log-id="${log.id}">
                    <span>
                        ${escapeHtml(eventTime)}
                    </span>

                    <span>
                        ${escapeHtml(log.source)}
                    </span>

                    <span>
                        ${escapeHtml(
                            log.description
                        )}
                    </span>

                    <span
                        class="log-status
                        ${statusClass(log.status)}"
                    >
                        ${escapeHtml(log.status)}
                    </span>
                </div>
            `;
        })
        .join("");

    container.innerHTML = header + rows;
}


// ==========================================
// الحوادث الأمنية
// ==========================================

async function loadIncidents() {
    const incidents =
        await fetchJson(API.incidents);

    const container =
        document.querySelector(".incident-list");

    if (!container) {
        return;
    }

    if (!incidents.length) {
        container.innerHTML = `
            <p class="empty-state">
                No active incidents found.
            </p>
        `;
        return;
    }

    container.innerHTML = incidents
        .slice(0, 4)
        .map((incident) => {
            const status =
                String(incident.status || "")
                    .toLowerCase();

            let statusStyle = "open";

            if (status === "investigating") {
                statusStyle =
                    "investigating";
            }

            if (
                status === "contained" ||
                status === "resolved"
            ) {
                statusStyle = "contained";
            }

            return `
                <div class="incident-item">
                    <div>
                        <span class="incident-number">
                            ${escapeHtml(
                                incident.incident_code
                            )}
                        </span>

                        <strong>
                            ${escapeHtml(
                                incident.title
                            )}
                        </strong>

                        <p>
                            ${escapeHtml(
                                incident.assigned_to ||
                                "Unassigned"
                            )}
                        </p>
                    </div>

                    <span
                        class="incident-status
                        ${statusStyle}"
                    >
                        ${escapeHtml(
                            incident.status
                        )}
                    </span>
                </div>
            `;
        })
        .join("");
}


// ==========================================
// حركة الرسم البياني
// ==========================================

function animateActivityChart() {
    const bars =
        document.querySelectorAll(
            ".chart-bars span"
        );

    bars.forEach((bar) => {
        const height =
            Math.floor(Math.random() * 65) + 25;

        bar.style.height = `${height}%`;
    });
}
function initializeActivityRange() {

    const activityRange = document.getElementById("activityRange");

    if (!activityRange) return;

    activityRange.addEventListener("change", function () {

        animateActivityChart();

        switch (this.value) {

            case "12h":
                alert("Displaying activity for the last 12 hours.");
                break;

            case "24h":
                alert("Displaying activity for the last 24 hours.");
                break;

            case "7d":
                alert("Displaying activity for the last 7 days.");
                break;

        }

    });

}
function showToast(message, type = "info") {

    const toast = document.getElementById("toast");

    if (!toast) return;

    toast.textContent = message;
    toast.className = `toast ${type} show`;

    setTimeout(() => {
        toast.classList.remove("show");
    }, 3000);
}
// ==========================================
// القائمة الجانبية
// ==========================================

function initializeNavigation() {
    const links =
        document.querySelectorAll(
            ".sidebar-nav .nav-link"
        );

    links.forEach((link) => {
        link.addEventListener(
            "click",
            () => {
                links.forEach((item) => {
                    item.classList.remove(
                        "active"
                    );
                });

                link.classList.add("active");
            }
        );
    });
}


// ==========================================
// تحميل جميع بيانات النظام
// ==========================================

async function loadDashboard() {
    try {
        await Promise.all([
            loadDashboardSummary(),
            loadAlerts(),
            loadSeverityDistribution(),
            loadSuspiciousIps(),
            loadLogs(),
            loadIncidents()
        ]);
        if (window.applyLogsFilters) {
    window.applyLogsFilters();
}

        console.log(
            "ShieldSOC data loaded successfully."
        );
    } catch (error) {
        console.error(
            "ShieldSOC loading error:",
            error
        );
    }
}


// ==========================================
// تشغيل النظام
// ==========================================

async function loadCurrentUser() {
    try {
        const response = await fetch("/api/session");

        if (response.status === 401) {
            window.location.href = "/login";
            return;
        }

        const data = await response.json();
        const user = data.user || {};

        const nameElement =
            document.getElementById("currentUserName");

        const roleElement =
            document.getElementById("currentUserRole");

        const initialsElement =
            document.getElementById("userInitials");

        if (nameElement) {
            nameElement.textContent =
                user.full_name ||
                user.username ||
                "SOC User";
        }

        if (roleElement) {
            roleElement.textContent =
                user.role || "Viewer";
        }
const usersNavLink =
    document.getElementById("usersNavLink");

const usersSection =
    document.getElementById("users");

const isAdministrator =
    user.role === "Administrator";

if (usersNavLink) {
    usersNavLink.style.display =
        isAdministrator ? "flex" : "none";
}

if (usersSection) {
    usersSection.hidden = !isAdministrator;
}
        if (initialsElement) {
            const initials = String(
                user.full_name ||
                user.username ||
                "SU"
            )
                .split(" ")
                .filter(Boolean)
                .slice(0, 2)
                .map((word) => word[0])
                .join("")
                .toUpperCase();

            initialsElement.textContent = initials;
        }
    } catch (error) {
        console.error(
            "Unable to load current user:",
            error
        );
    }
}


async function logoutUser() {
    const button =
        document.getElementById("logoutButton");

    if (button) {
        button.disabled = true;
        button.textContent = "Signing out...";
    }

    try {
        const response = await fetch("/api/logout", {
            method: "POST"
        });

        if (!response.ok) {
            throw new Error("Logout failed");
        }

        window.location.href = "/login";
    } catch (error) {
        console.error("Logout error:", error);

        if (button) {
            button.disabled = false;
            button.textContent = "Logout";
        }
    }
}


function initializeUserSession() {
    loadCurrentUser();

    const logoutButton =
        document.getElementById("logoutButton");

    if (logoutButton) {
        logoutButton.addEventListener(
            "click",
            logoutUser
        );
    }
}
const editUserModal = document.getElementById("editUserModal");
const editUserForm = document.getElementById("editUserForm");
const editUserId = document.getElementById("editUserId");
const editFullName = document.getElementById("editFullName");
const editUsername = document.getElementById("editUsername");
const editRole = document.getElementById("editRole");
const editIsActive = document.getElementById("editIsActive");
const editUserMessage = document.getElementById("editUserMessage");
const closeEditUserButton = document.getElementById("closeEditUserButton");
const saveEditUserButton = document.getElementById("saveEditUserButton");

const usersSearchInput =
    document.getElementById("usersSearchInput");

async function loadUsers() {
    const usersTableBody =
        document.getElementById("usersTableBody");

    if (!usersTableBody) {
        return;
    }

    usersTableBody.innerHTML = `
        <div class="user-loading">
            Loading users...
        </div>
    `;

    try {
        const response = await fetch("/api/admin/users");

        if (response.status === 401) {
            window.location.href = "/login";
            return;
        }

        if (response.status === 403) {
            usersTableBody.innerHTML = `
                <div class="user-error">
                    You do not have permission to view users.
                </div>
            `;
            return;
        }

        const result = await response.json();

        if (!response.ok || !result.success) {
            throw new Error(
                result.message || "Unable to load users."
            );
        }

        const users = result.users || [];
        window.shieldSocUsers = users;
        if (users.length === 0) {
            usersTableBody.innerHTML = `
                <div class="user-empty">
                    No users found.
                </div>
            `;
            return;
        }

        usersTableBody.innerHTML = users
            .map((user) => {
                const statusClass =
                    Number(user.is_active) === 1
                        ? "active"
                        : "inactive";

                const statusText =
                    Number(user.is_active) === 1
                        ? "Active"
                        : "Inactive";

                const createdDate = user.created_at
    ? new Date(
        user.created_at.replace(" ", "T")
      ).toLocaleDateString("en-GB", {
            day: "2-digit",
            month: "short",
            year: "numeric"
        })
    : "--";

                return `
                    <div class="user-row">
                        <span>
                            ${escapeHtml(user.full_name || "—")}
                        </span>

                        <span>
                            ${escapeHtml(user.username || "—")}
                        </span>

                        <span class="user-role">
                            ${escapeHtml(user.role || "Viewer")}
                        </span>

                        <span>
                            <span class="user-status ${statusClass}">
                                ${statusText}
                            </span>
                        </span>

                        <span>
                            ${createdDate}
                        </span>
                        <span class="user-actions">

    <button
        type="button"
        class="edit-user-button"
        data-user-id="${user.id}"
        data-full-name="${escapeHtml(user.full_name || "")}"
        data-username="${escapeHtml(user.username || "")}"
        data-role="${user.role}"
        data-active="${user.is_active}"
    >
        ✏️ Edit
    </button>

    <button
        type="button"
        class="delete-user-button"
        data-user-id="${user.id}"
        data-username="${escapeHtml(user.username || "")}"
    >
        🗑 Delete
    </button>

</span>
                        
                    </div>
                `;
            })
            .join("");

    } catch (error) {
        console.error("Load users error:", error);

        usersTableBody.innerHTML = `
            <div class="user-error">
                Unable to load users.
            </div>
        `;
    }
}
document.addEventListener("click", (event) => {

    const editButton = event.target.closest(".edit-user-button");

    if (!editButton) return;

    editUserId.value = editButton.dataset.userId;
    editFullName.value = editButton.dataset.fullName;
    editUsername.value = editButton.dataset.username;
    editRole.value = editButton.dataset.role;
    editIsActive.checked = editButton.dataset.active === "1";

    editUserMessage.hidden = true;
    editUserModal.hidden = false;

});
closeEditUserButton.addEventListener("click", () => {
    editUserModal.hidden = true;
    editUserForm.reset();
    editUserMessage.hidden = true;
});

editUserModal.addEventListener("click", (event) => {
    if (event.target === editUserModal) {
        editUserModal.hidden = true;
        editUserForm.reset();
        editUserMessage.hidden = true;
    }
});

editUserForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    saveEditUserButton.disabled = true;
    saveEditUserButton.textContent = "Saving...";

    try {

        const response = await fetch(`/api/admin/users/${editUserId.value}`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                full_name: editFullName.value,
                username: editUsername.value,
                role: editRole.value,
                is_active: editIsActive.checked
            })
        });

        const result = await response.json();

        editUserMessage.hidden = false;
        editUserMessage.textContent = result.message;

        if (result.success) {

            showToast("User updated successfully.", "success");
            editUserMessage.className = "login-message success";

            editUserModal.hidden = true;

            loadUsers();

        } else {
            showToast(requestAnimationFrame.message || "Unable to update user.", "error");

            editUserMessage.className = "login-message error";

        }

    } catch (error) {

        editUserMessage.hidden = false;
        editUserMessage.className = "login-message error";
        editUserMessage.textContent = "Unable to update user.";
        showToast("Unable to update user.", "error");

    } finally {

        saveEditUserButton.disabled = false;
        saveEditUserButton.textContent = "Save Changes";

    }

});

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


function initializeUsersManagement() {
    const usersNavLink =
        document.getElementById("usersNavLink");

    const usersSection =
        document.getElementById("users");

    if (!usersNavLink || !usersSection) {
        return;
    }

    usersNavLink.addEventListener("click", async (event) => {
        event.preventDefault();

        document.querySelectorAll(".nav-link").forEach((link) => {
            link.classList.remove("active");
        });

        usersNavLink.classList.add("active");

        document
            .querySelectorAll(
                ".main-content > section"
            )
            .forEach((section) => {
                section.hidden = true;
            });

        usersSection.hidden = false;

        await loadUsers();

        usersSection.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });
    });
}
if (usersSearchInput) {
    usersSearchInput.addEventListener("input", function () {
        const keyword = this.value.trim().toLowerCase();

        const userRows = document.querySelectorAll(
            "#usersTableBody .user-row"
        );

        userRows.forEach((row) => {
            const rowText = row.textContent
                .trim()
                .toLowerCase();

            row.style.display =
                rowText.includes(keyword) ? "" : "none";
        });
    });
}
function initializeAddUserModal() {
    const addUserButton = document.getElementById("addUserButton");
    const addUserModal = document.getElementById("addUserModal");
    const closeModalButton = document.getElementById("closeModalButton");

    if (!addUserButton || !addUserModal || !closeModalButton) {
        return;
    }

    addUserButton.addEventListener("click", () => {
        addUserModal.hidden = false;
    });

    closeModalButton.addEventListener("click", () => {
        addUserModal.hidden = true;
    });

    addUserModal.addEventListener("click", (event) => {
        if (event.target === addUserModal) {
            addUserModal.hidden = true;
        }
    });
}
const saveUserButton = document.getElementById("saveUserButton");

saveUserButton.addEventListener("click", async () => {
    const full_name = document.getElementById("newFullName").value.trim();
    const username = document.getElementById("newUsername").value.trim();
    const password = document.getElementById("newPassword").value;
    const role = document.getElementById("newRole").value;

    const response = await fetch("/api/admin/users", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            full_name,
            username,
            password,
            role
        })
    });

    const result = await response.json();

    if (result.success) {
        showToast("User created successfully.", "success");
        addUserModal.hidden = true;
        await loadUsers();
    } else {
        showToast(result.message, "error");
    }
});
document.addEventListener("click", async (event) => {
    const deleteButton = event.target.closest(".delete-user-button");

    if (!deleteButton) {
        return;
    }

    const userId = deleteButton.dataset.userId;
    const username = deleteButton.dataset.username || "this user";

    const confirmed = confirm(
        `Are you sure you want to delete ${username}?`
    );

    if (!confirmed) {
        return;
    }

    deleteButton.disabled = true;
    deleteButton.textContent = "Deleting...";

    try {
        const response = await fetch(
            `/api/admin/users/${userId}`,
            {
                method: "DELETE"
            }
        );

        const result = await response.json();

        if (response.status === 401) {
            window.location.href = "/login";
            return;
        }

        if (!response.ok || !result.success) {
            throw new Error(
                result.message || "Unable to delete user."
            );
        }

showToast("User deleted successfully.", "success");
        await loadUsers();

    } catch (error) {
        alert(error.message);
        deleteButton.disabled = false;
        deleteButton.textContent = "Delete";
    }
});
async function exportLogs() {
    try {
        const response = await fetch("/api/logs");

        if (!response.ok) {
            throw new Error("Unable to export logs.");
        }

        const logs = await response.json();

        if (!Array.isArray(logs) || logs.length === 0) {
            showToast("No logs available to export.", "info");
            return;
        }

        const headers = [
            "Time",
            "Source",
            "Event",
            "Severity",
            "Source IP",
            "Destination IP",
            "Environment",
            "Status"
        ];

        const rows = logs.map((log) => [
            log.event_time || "",
            log.source || "",
            log.description || "",
            log.severity || "",
            log.source_ip || "",
            log.destination_ip || "",
            log.environment || "",
            log.status || ""
        ]);

        const csvContent = [headers, ...rows]
            .map((row) =>
                row
                    .map((value) =>
                        `"${String(value).replaceAll('"', '""')}"`
                    )
                    .join(",")
            )
            .join("\n");

        const blob = new Blob([csvContent], {
            type: "text/csv;charset=utf-8;"
        });

        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");

        link.href = url;
        link.download = `shieldsoc-logs-${new Date()
            .toISOString()
            .slice(0, 10)}.csv`;

        document.body.appendChild(link);
        link.click();
        link.remove();

        URL.revokeObjectURL(url);
        showToast("Logs exported successfully.", "success");
    } catch (error) {
        showToast(error.message, "error");
    }
}

function initializeExportLogs() {
    const exportButton =
        document.getElementById("exportLogsButton");

    if (!exportButton) {
        return;
    }

    exportButton.addEventListener("click", exportLogs);
}
function initializeLogsFilters() {
    const searchInput = document.getElementById("logsSearchInput");
    const statusFilter = document.getElementById("logsStatusFilter");

    if (!searchInput || !statusFilter) {
        return;
    }

    function filterLogs() {
        const keyword = searchInput.value.trim().toLowerCase();
        const status = statusFilter.value.toLowerCase();

        const rows = document.querySelectorAll(".logs-table .log-row");

        rows.forEach((row, index) => {
            if (index === 0) return; // تجاهل الهيدر

            const text = row.textContent.toLowerCase();

            const keywordMatch = text.includes(keyword);
            const statusMatch =
                !status || text.includes(status);

           const shouldShow = keywordMatch && statusMatch;

row.style.setProperty(
    "display",
    shouldShow ? "grid" : "none",
    "important"
);
        });
    }
window.applyLogsFilters = filterLogs;
    searchInput.addEventListener("input", filterLogs);
    statusFilter.addEventListener("change", filterLogs);
    filterLogs();
    
}
const assignButton = document.getElementById("assignAlertButton");
const resolveButton = document.getElementById("resolveAlertButton");

if (assignButton) {
    assignButton.addEventListener("click", async () => {

        const logId = assignButton.dataset.logId;

        if (!logId) {
            showToast("Log ID not found.", "error");
            return;
        }

        assignButton.disabled = true;
        assignButton.textContent = "Assigning...";

        try {

            const response = await fetch(
                `/api/logs/${logId}/assign`,
                {
                    method: "PUT"
                }
            );

            const result = await response.json();

            if (!response.ok || !result.success) {
                throw new Error(result.message || "Unable to assign analyst.");
            }

            document.getElementById("detailAssignedAnalyst").textContent =
                "SOC Analyst - Salma";

            showToast(
                "Alert assigned successfully.",
                "success"
            );

            await loadLogs();

        } catch (error) {

            showToast(error.message, "error");

        } finally {

            assignButton.disabled = false;
            assignButton.textContent = "Assign to Analyst";

        }

    });
}

if (resolveButton) {
    resolveButton.addEventListener("click", async () => {
        const logId = resolveButton.dataset.logId;

        if (!logId) {
            showToast("Log ID not found.", "error");
            return;
        }

        resolveButton.disabled = true;
        resolveButton.textContent = "Resolving...";

        try {
            const response = await fetch(
                `/api/logs/${logId}/resolve`,
                {
                    method: "PUT"
                }
            );

            const result = await response.json();

            if (!response.ok || !result.success) {
                throw new Error(
                    result.message || "Unable to resolve log."
                );
            }

            document.getElementById("detailStatus").textContent =
                "Resolved";

            showToast(
                "Alert marked as resolved.",
                "success"
            );

            await loadLogs();
            await loadDashboardSummary();
        } catch (error) {
            showToast(error.message, "error");
        } finally {
            resolveButton.disabled = false;
            resolveButton.textContent = "✓ Mark as Resolved";
        }
    });
}
function initializeLogDetails() {
    const modal = document.getElementById("logDetailsModal");
    const closeButton = document.getElementById("closeLogDetails");

    const detailTime = document.getElementById("detailTime");
    const detailSource = document.getElementById("detailSource");
    const detailEvent = document.getElementById("detailEvent");
    const detailStatus = document.getElementById("detailStatus");
    const detailRecommendation =
        document.getElementById("detailRecommendation");

    if (
        !modal ||
        !closeButton ||
        !detailTime ||
        !detailSource ||
        !detailEvent ||
        !detailStatus ||
        !detailRecommendation
    ) {
        return;
    }

    document.addEventListener("click", (event) => {
        const row = event.target.closest(".logs-table .log-row");

        if (!row || row.classList.contains("log-header")) {
            return;
        }
        const logId = row.dataset.logId;

        const columns = row.querySelectorAll(":scope > span");

        if (columns.length < 4) {
            return;
        }

        const time = columns[0].textContent.trim();
        const source = columns[1].textContent.trim();
        const eventText = columns[2].textContent.trim();
        const status = columns[3].textContent.trim();

        let recommendation =
            "Review the event, validate the affected endpoint, and document the investigation.";

        if (status.toLowerCase().includes("blocked")) {
            recommendation =
                "Verify that the block was successful and review related traffic for additional indicators.";
        } else if (
            status.toLowerCase().includes("new") ||
            status.toLowerCase().includes("alert")
        ) {
            recommendation =
                "Investigate immediately, identify the source, and determine whether escalation is required.";
        } else if (
            status.toLowerCase().includes("investigating") ||
            status.toLowerCase().includes("review")
        ) {
            recommendation =
                "Continue the investigation, collect evidence, and update the incident timeline.";
        } else if (
            status.toLowerCase().includes("resolved") ||
            status.toLowerCase().includes("normal")
        ) {
            recommendation =
                "Confirm remediation, document the resolution, and close the event if no further activity is detected.";
        }

        detailTime.textContent = time;
        detailSource.textContent = source;
        detailEvent.textContent = eventText;
        detailStatus.textContent = status;
        detailRecommendation.textContent = recommendation;
resolveButton.dataset.logId = logId;
assignButton.dataset.logId = logId;
        modal.style.display = "flex";
        Object.assign(modal.style, {
    position: "fixed",
    inset: "0",
    width: "100vw",
    height: "100vh",
    alignItems: "center",
    justifyContent: "center",
    background: "rgba(2,12,35,0.78)",
    backdropFilter: "blur(6px)",
    zIndex: "99999",
    padding: "20px"
});

const modalContent = modal.querySelector(".modal-content");

if (modalContent) {
    Object.assign(modalContent.style, {
        position: "relative",
        width: "min(650px, 92vw)",
        maxHeight: "85vh",
        overflowY: "auto",
        margin: "0"
    });
}
    });

    closeButton.addEventListener("click", () => {
        modal.style.display = "none";
    });

    modal.addEventListener("click", (event) => {
        if (event.target === modal) {
            modal.style.display = "none";
        }
    });
}
function initializeRefreshDashboard() {
    const refreshButton = document.getElementById("refreshDashboardButton");
    const lastUpdatedText = document.getElementById("lastUpdatedText");

    if (!refreshButton) return;

    refreshButton.addEventListener("click", async () => {
        refreshButton.disabled = true;
        refreshButton.textContent = "Refreshing...";

        await loadDashboard();

        if (lastUpdatedText) {
            const now = new Date().toLocaleTimeString();
            lastUpdatedText.textContent = `Last updated: ${now}`;
        }

        showToast("Dashboard refreshed successfully.", "success");

        refreshButton.disabled = false;
        refreshButton.innerHTML = "↻ Refresh";
    });
}

function initializeViewAllAlerts() {

    const button = document.getElementById("viewAllAlerts");

    if (!button) return;

    button.addEventListener("click", () => {

        const alertsSection = document.querySelector(".alerts-table");

        alertsSection.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });

    });

}

function initializeNotifications() {

    const button = document.getElementById("notificationsButton");
    const popup = document.getElementById("notificationPopup");

    if (!button || !popup) return;

    button.addEventListener("click", (e) => {
        e.stopPropagation();

        popup.style.display =
            popup.style.display === "block"
                ? "none"
                : "block";
    });

    document.addEventListener("click", (e) => {
        if (
            !popup.contains(e.target) &&
            e.target !== button
        ) {
            popup.style.display = "none";
        }
    });

}
let dashboardRefreshTimer = null;

function initializeSettings() {
    const settingsButton = document.getElementById("settingsButton");
    const settingsModal = document.getElementById("settingsModal");
    const closeSettingsButton = document.getElementById("closeSettingsButton");
    const saveSettingsButton = document.getElementById("saveSettingsButton");
    const autoRefreshToggle = document.getElementById("autoRefreshToggle");
    const refreshInterval = document.getElementById("refreshInterval");

    if (
        !settingsButton ||
        !settingsModal ||
        !closeSettingsButton ||
        !saveSettingsButton ||
        !autoRefreshToggle ||
        !refreshInterval
    ) {
        return;
    }

    settingsButton.addEventListener("click", (event) => {
        event.preventDefault();
        settingsModal.hidden = false;
    });

    closeSettingsButton.addEventListener("click", () => {
        settingsModal.hidden = true;
    });

    settingsModal.addEventListener("click", (event) => {
        if (event.target === settingsModal) {
            settingsModal.hidden = true;
        }
    });

    saveSettingsButton.addEventListener("click", () => {
        if (dashboardRefreshTimer) {
            clearInterval(dashboardRefreshTimer);
            dashboardRefreshTimer = null;
        }

        if (autoRefreshToggle.checked) {
            const interval = Number(refreshInterval.value);

            dashboardRefreshTimer = setInterval(
                loadDashboard,
                interval
            );
        }

        settingsModal.hidden = true;
        alert("Settings saved successfully.");
    });
}
function initializeSupport() {

    const supportButton = document.getElementById("supportButton");
    const supportModal = document.getElementById("supportModal");
    const closeSupportButton = document.getElementById("closeSupportButton");
    const ticketButton = document.getElementById("ticketButton");

    if (!supportButton) return;

    supportButton.addEventListener("click", (e) => {
        e.preventDefault();
        supportModal.hidden = false;
    });

    closeSupportButton.addEventListener("click", () => {
        supportModal.hidden = true;
    });

    supportModal.addEventListener("click", (e) => {
        if (e.target === supportModal) {
            supportModal.hidden = true;
        }
    });

    ticketButton.addEventListener("click", () => {
        alert("Support ticket submitted successfully.");
    });

}
async function loadDynamicAlerts() {
    const alertsTableBody = document.getElementById("alertsTableBody");

    if (!alertsTableBody) return;

    alertsTableBody.innerHTML = `
        <div class="user-loading">
            Loading alerts...
        </div>
    `;

    try {
        const response = await fetch("/api/alerts");

        if (!response.ok) {
            throw new Error("Unable to load alerts.");
        }

        const alerts = await response.json();

        if (!Array.isArray(alerts) || alerts.length === 0) {
            alertsTableBody.innerHTML = `
                <div class="user-empty">
                    No security alerts found.
                </div>
            `;
            return;
        }

        alertsTableBody.innerHTML = alerts
            .slice(0, 4)
            .map((alert) => {
                const severity = String(alert.severity || "low").toLowerCase();

                return `
                    <div class="alert-row">
                        <span class="severity-badge ${severity}">
                            ${escapeHtml(alert.severity || "Low")}
                        </span>

                        <div class="alert-details">
                            <strong>
                                ${escapeHtml(alert.alert_title || "Security Alert")}
                            </strong>

                            <p>
                                Source IP: ${escapeHtml(alert.source_ip || "Unknown")}
                            </p>
                        </div>

                        <div class="alert-source">
                            <span>${escapeHtml(alert.environment || "Unknown")}</span>
                            <small>${escapeHtml(alert.source || "Unknown")}</small>
                        </div>

                        <time>
                            ${escapeHtml(alert.detected_at || "Just now")}
                        </time>
                    </div>
                `;
            })
            .join("");
    } catch (error) {
        alertsTableBody.innerHTML = `
            <div class="user-error">
                ${escapeHtml(error.message)}
            </div>
        `;
    }
}
document.addEventListener(
    "DOMContentLoaded",
    () => {
        initializeNavigation();
        initializeUserSession();
        loadDashboard();
        animateActivityChart();
        initializeUsersManagement();
        initializeAddUserModal();
        initializeExportLogs();
        initializeActivityRange();
        initializeViewAllAlerts();
        initializeNotifications();
        initializeSettings();
        initializeSupport();
        initializeLogsFilters();
        initializeLogDetails();
        initializeRefreshDashboard();
        loadDashboard();
        loadDynamicAlerts();

        // تحديث البيانات كل 10 ثوانٍ
        
        setInterval(
            loadDashboard,
            10000
        );

        // تحريك الرسم كل 4 ثوانٍ
        setInterval(
            animateActivityChart,
            4000
        );
    }
);