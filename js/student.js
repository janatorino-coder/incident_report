document.addEventListener("DOMContentLoaded", () => {
    const search = document.getElementById("reportSearch");
    const filter = document.getElementById("statusFilter");
    const list = document.getElementById("allReportsList");
    const empty = document.getElementById("noMatches");

    const normalise = value => {
        const v = String(value || "").toLowerCase().trim();
        return ["under review", "in_review"].includes(v) ? "review" : v;
    };

    function filterReports() {
        if (!list) return;
        const term = (search?.value || "").toLowerCase().trim();
        const selected = normalise(filter?.value || "all");
        const rows = [...list.querySelectorAll(".report-row")];
        let visible = 0;
        rows.forEach(row => {
            const textMatch = !term || (row.dataset.search || "").includes(term);
            const statusMatch = selected === "all" || normalise(row.dataset.status) === selected;
            row.hidden = !(textMatch && statusMatch);
            if (!row.hidden) visible++;
        });
        if (empty) empty.hidden = visible > 0 || rows.length === 0;
    }
    search?.addEventListener("input", filterReports);
    filter?.addEventListener("change", filterReports);

    const reportDialog = document.getElementById("reportDialog");
    document.querySelectorAll(".view-report").forEach(button => {
        button.addEventListener("click", () => {
            const id = Number(button.dataset.id || 0);
            const setText = (id, value) => {
                const el = document.getElementById(id);
                if (el) el.textContent = value || "—";
            };
            setText("modalId", "REPORT #INC-" + String(id).padStart(4, "0"));
            setText("modalCategory", button.dataset.category || "Incident report");
            const status = document.getElementById("modalStatus");
            if (status) {
                status.textContent = button.dataset.status || "Pending";
                status.className = "status-pill " + normalise(status.textContent);
            }
            setText("modalSeverity", "Severity: " + (button.dataset.severity || "Not specified"));
            setText("modalDate", button.dataset.date || "");
            setText("modalLocation", button.dataset.location || "Not provided");
            setText("modalDescription", button.dataset.description || "No description provided.");
            if (reportDialog && typeof reportDialog.showModal === "function") reportDialog.showModal();
        });
    });

    const helpDialog = document.getElementById("helpDialog");
    document.getElementById("helpButton")?.addEventListener("click", () => helpDialog?.showModal());
    document.getElementById("privacyReview")?.addEventListener("click", () => {
        window.alert("Your account identity is not shown in the student All reports list. Authorized administrators can access report details for follow-up.");
    });

    document.querySelectorAll("[data-setting]").forEach(input => {
        const key = "sirs_student_" + input.dataset.setting;
        try {
            const saved = localStorage.getItem(key);
            if (saved !== null) input.checked = saved === "true";
            input.addEventListener("change", () => localStorage.setItem(key, String(input.checked)));
        } catch (_) { /* Browser storage may be disabled. */ }
    });

    document.getElementById("incidentForm")?.addEventListener("submit", event => {
        const button = event.currentTarget.querySelector('button[type="submit"]');
        if (button) {
            button.disabled = true;
            button.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Submitting...';
        }
    });

    filterReports();
});
