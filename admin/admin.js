document.addEventListener("DOMContentLoaded", function () {
    const dashboardData = window.SIRS_DASHBOARD_DATA || {
        total: 0,
        weekly: { labels: [], values: [] },
        monthly: { labels: [], values: [] },
        categories: []
    };

    const navItems = Array.from(document.querySelectorAll(".nav-item[data-page]"));
    const viewSections = Array.from(document.querySelectorAll("[data-view]"));
    const breadcrumbCurrent = document.getElementById("breadcrumbCurrent");
    const createReportModal = document.getElementById("createReportModal");
    const detailsModal = document.getElementById("detailsModal");

    let activeModal = null;
    let trendChart = null;
    let categoryChart = null;
    let currentRange = "weekly";

    // -------------------------
    // NAVIGATION
    // -------------------------

    function goToPage(pageName) {
        const target = viewSections.find(
            section => section.dataset.view === pageName
        );

        if (!target) return;

        viewSections.forEach(section => {
            const isActive = section === target;

            section.hidden = !isActive;
            section.classList.toggle("active-view", isActive);
        });

        navItems.forEach(item => {
            const isActive = item.dataset.page === pageName;

            item.classList.toggle("active", isActive);

            if (isActive) {
                item.setAttribute("aria-current", "page");
            } else {
                item.removeAttribute("aria-current");
            }
        });

        const activeItem = navItems.find(
            item => item.dataset.page === pageName
        );

        if (breadcrumbCurrent && activeItem) {
            breadcrumbCurrent.textContent =
                activeItem.dataset.title || activeItem.innerText.trim();
        }

        if (pageName === "dashboard") {
            window.requestAnimationFrame(() => {
                renderCharts(currentRange);
            });
        }

        window.scrollTo({
            top: 0,
            behavior: "smooth"
        });
    }

    navItems.forEach(item => {
        item.addEventListener("click", () => {
            goToPage(item.dataset.page);
        });
    });

    document.querySelectorAll("[data-go-page]").forEach(button => {
        button.addEventListener("click", () => {
            closeModal();
            goToPage(button.dataset.goPage);
        });
    });

    const notificationsButton =
        document.getElementById("notificationsButton");

    if (notificationsButton) {
        notificationsButton.addEventListener("click", () => {
            goToPage("notifications");
        });
    }

    // -------------------------
    // MODALS
    // -------------------------

    function openModal(modal) {
        if (!modal) return;

        closeModal();

        modal.hidden = false;
        activeModal = modal;

        document.body.style.overflow = "hidden";

        const firstField = modal.querySelector(
            "input:not([type=hidden]), select, textarea, button"
        );

        if (firstField) {
            window.setTimeout(() => firstField.focus(), 30);
        }
    }

    function closeModal() {
        if (activeModal) {
            activeModal.hidden = true;
        }

        activeModal = null;
        document.body.style.overflow = "";
    }

    document.querySelectorAll(".open-report-modal").forEach(button => {
        button.addEventListener("click", () => {
            openModal(createReportModal);
        });
    });

    document.querySelectorAll("[data-close-modal]").forEach(button => {
        button.addEventListener("click", closeModal);
    });

    [createReportModal, detailsModal].forEach(modal => {
        if (!modal) return;

        modal.addEventListener("click", event => {
            if (event.target === modal) {
                closeModal();
            }
        });
    });

    document.addEventListener("keydown", event => {
        if (event.key === "Escape" && activeModal) {
            closeModal();
        }
    });

    // -------------------------
    // INCIDENT DETAILS
    // -------------------------

    const detailFields = {
        reportId: document.getElementById("detailReportId"),
        student: document.getElementById("detailStudent"),
        grade: document.getElementById("detailGrade"),
        category: document.getElementById("detailCategory"),
        severity: document.getElementById("detailSeverity"),
        status: document.getElementById("detailStatus"),
        date: document.getElementById("detailDate"),
        description: document.getElementById("detailDescription")
    };

    function showDetails(button) {
        const fields = {
            reportId: "reportId",
            student: "student",
            grade: "grade",
            category: "category",
            severity: "severity",
            status: "status",
            date: "date",
            description: "description"
        };

        Object.entries(fields).forEach(([elementKey, dataKey]) => {
            const element = detailFields[elementKey];

            if (!element) return;

            const value = button.dataset[dataKey] || "";

            if (elementKey === "description") {
                element.textContent =
                    value || "No description was provided.";
            } else {
                element.textContent = value || "—";
            }
        });

        openModal(detailsModal);
    }

    document.querySelectorAll(".view-details").forEach(button => {
        button.addEventListener("click", () => {
            showDetails(button);
        });
    });

    // -------------------------
    // ALERTS AND FORM FEEDBACK
    // -------------------------

    document.querySelectorAll(".alert-close").forEach(button => {
        button.addEventListener("click", () => {
            button.closest(".alert")?.remove();
        });
    });

    const createIncidentForm =
        document.getElementById("createIncidentForm");

    if (createIncidentForm) {
        createIncidentForm.addEventListener("submit", function () {
            const submitButton = createIncidentForm.querySelector(
                'button[type="submit"]'
            );

            if (submitButton) {
                submitButton.disabled = true;

                submitButton.innerHTML =
                    '<i class="fa-solid fa-spinner fa-spin"></i> Saving…';
            }
        });
    }

    document.querySelectorAll(".status-form").forEach(form => {
        form.addEventListener("submit", function (event) {
            if (!window.confirm("Save this incident status change?")) {
                event.preventDefault();
                return;
            }

            const saveButton = form.querySelector(
                'button[type="submit"]'
            );

            if (saveButton) {
                saveButton.disabled = true;
                saveButton.textContent = "Saving…";
            }
        });
    });

    // -------------------------
    // INCIDENT SEARCH AND FILTER
    // -------------------------

    const incidentSearch =
        document.getElementById("incidentSearch");

    const statusFilter =
        document.getElementById("statusFilter");

    const filterCount =
        document.getElementById("filterCount");

    const filteredEmpty =
        document.getElementById("filteredEmpty");

    const incidentRows = Array.from(
        document.querySelectorAll("#incidentsTable .incident-row")
    );

    function filterIncidents() {
        const term = (incidentSearch?.value || "")
            .trim()
            .toLowerCase();

        const status = (
            statusFilter?.value || "all"
        ).toLowerCase();

        let visible = 0;

        incidentRows.forEach(row => {
            const searchableText =
                row.dataset.search || row.innerText.toLowerCase();

            const rowStatus =
                (row.dataset.status || "").toLowerCase();

            const matchesText =
                !term || searchableText.includes(term);

            const matchesStatus =
                status === "all" || rowStatus === status;

            const show = matchesText && matchesStatus;

            row.hidden = !show;

            if (show) {
                visible++;
            }
        });

        if (filterCount) {
            filterCount.textContent =
                `${visible} report${visible === 1 ? "" : "s"} shown`;
        }

        if (filteredEmpty) {
            filteredEmpty.hidden =
                visible !== 0 || incidentRows.length === 0;
        }
    }

    if (incidentSearch) {
        incidentSearch.addEventListener("input", filterIncidents);
    }

    if (statusFilter) {
        statusFilter.addEventListener("change", filterIncidents);
    }

    // -------------------------
    // CHARTS FROM PHP / MYSQL DATA
    // -------------------------

    const chartColors = [
        "#1f7a52",
        "#2563a8",
        "#b7791f",
        "#0f8a76",
        "#8b5cf6",
        "#d46c57",
        "#7c8f88",
        "#68a5a0"
    ];

    function updateChartEmptyState(
        canvasId,
        hasData,
        messageTitle,
        messageBody
    ) {
        const shell = document.querySelector(
            `[data-chart-shell="${canvasId}"]`
        );

        const canvas = document.getElementById(canvasId);

        if (!shell || !canvas) return;

        const empty = shell.querySelector(".chart-empty");

        canvas.hidden = !hasData;

        if (empty) {
            empty.hidden = hasData;

            const strong = empty.querySelector("strong");
            const span = empty.querySelector("span");

            if (strong) {
                strong.textContent = messageTitle;
            }

            if (span) {
                span.textContent = messageBody;
            }
        }
    }

    // -------------------------
    // INCIDENT TREND CHART
    // -------------------------

    function renderTrendChart(range) {
        const canvas = document.getElementById("trendChart");

        if (!canvas || typeof Chart === "undefined") return;

        const data = dashboardData[range] || {
            labels: [],
            values: []
        };

        const hasDataInRange = (data.values || []).some(
            value => Number(value) > 0
        );

        updateChartEmptyState(
            "trendChart",
            hasDataInRange,
            "No reports in this period",
            "New submissions will appear in this chart."
        );

        if (trendChart) {
            trendChart.destroy();
            trendChart = null;
        }

        if (!hasDataInRange) return;

        trendChart = new Chart(canvas, {
            type: "line",

            data: {
                labels: data.labels,

                datasets: [{
                    label: "Incident reports",
                    data: data.values,
                    borderColor: "#1f7a52",
                    backgroundColor: "rgba(31, 122, 82, 0.10)",
                    borderWidth: 2.5,
                    tension: 0.35,
                    fill: true,
                    pointRadius: 3,
                    pointHoverRadius: 5,
                    pointBackgroundColor: "#1f7a52"
                }]
            },

            options: {
                responsive: true,
                maintainAspectRatio: false,

                interaction: {
                    intersect: false,
                    mode: "index"
                },

                plugins: {
                    legend: {
                        display: false
                    },

                    tooltip: {
                        callbacks: {
                            label: context =>
                                ` ${context.parsed.y} report(s)`
                        }
                    }
                },

                scales: {
                    y: {
                        beginAtZero: true,

                        ticks: {
                            precision: 0,
                            color: "#6b756f",
                            font: {
                                size: 11
                            }
                        },

                        grid: {
                            color: "#eef0f2"
                        }
                    },

                    x: {
                        ticks: {
                            color: "#6b756f",
                            font: {
                                size: 11
                            }
                        },

                        grid: {
                            display: false
                        }
                    }
                }
            }
        });
    }

    // -------------------------
    // INCIDENT CATEGORY CHART
    // -------------------------

    function renderCategoryChart() {
        const canvas =
            document.getElementById("categoryChart");

        const legend =
            document.getElementById("categoryLegend");

        if (!canvas || typeof Chart === "undefined") return;

        const categories = Array.isArray(dashboardData.categories)
            ? dashboardData.categories
            : [];

        const categoryTotal = categories.reduce(
            (sum, item) => sum + Number(item.value || 0),
            0
        );

        const hasCategories =
            categoryTotal > 0 && categories.length > 0;

        updateChartEmptyState(
            "categoryChart",
            hasCategories,
            "No categories yet",
            "Category breakdown appears after a report is submitted."
        );

        if (categoryChart) {
            categoryChart.destroy();
            categoryChart = null;
        }

        if (legend) {
            legend.replaceChildren();
        }

        if (!hasCategories) return;

        categoryChart = new Chart(canvas, {
            type: "doughnut",

            data: {
                labels: categories.map(
                    item => String(item.label || "Other")
                ),

                datasets: [{
                    data: categories.map(
                        item => Number(item.value || 0)
                    ),

                    backgroundColor: categories.map(
                        (item, index) =>
                            item.color ||
                            chartColors[index % chartColors.length]
                    ),

                    borderWidth: 0,
                    hoverOffset: 5
                }]
            },

            options: {
                responsive: false,
                cutout: "68%",

                plugins: {
                    legend: {
                        display: false
                    },

                    tooltip: {
                        callbacks: {
                            label: context => {
                                const value = Number(
                                    context.parsed || 0
                                );

                                const percent = categoryTotal
                                    ? Math.round(
                                        (value / categoryTotal) * 100
                                    )
                                    : 0;

                                return ` ${context.label}: ${value} (${percent}%)`;
                            }
                        }
                    }
                }
            }
        });

        categories.forEach((category, index) => {
            const value = Number(category.value || 0);

            const percent = categoryTotal
                ? Math.round((value / categoryTotal) * 100)
                : 0;

            const li = document.createElement("li");

            const labelWrap = document.createElement("span");
            const dot = document.createElement("span");
            const label = document.createElement("span");
            const stats = document.createElement("span");

            dot.className = "legend-dot";

            dot.style.backgroundColor =
                chartColors[index % chartColors.length];

            label.textContent =
                String(category.label || "Other");

            labelWrap.append(dot, label);

            stats.className = "pct";
            stats.textContent = `${value} · ${percent}%`;

            li.append(labelWrap, stats);

            legend?.appendChild(li);
        });
    }

    // -------------------------
    // RENDER CHARTS
    // -------------------------

    function renderCharts(range) {
        currentRange = range || currentRange;

        renderTrendChart(currentRange);
        renderCategoryChart();
    }

    document.querySelectorAll("[data-range]").forEach(button => {
        button.addEventListener("click", () => {
            document.querySelectorAll("[data-range]").forEach(item => {
                item.classList.toggle("active", item === button);
            });

            renderTrendChart(button.dataset.range || "weekly");
        });
    });

    // -------------------------
    // CHART LIBRARY CHECK
    // -------------------------

    if (typeof Chart === "undefined") {
        document.querySelectorAll(".chart-shell").forEach(shell => {
            const empty = shell.querySelector(".chart-empty");

            if (empty) {
                empty.hidden = false;

                const strong = empty.querySelector("strong");
                const span = empty.querySelector("span");

                if (strong) {
                    strong.textContent = "Chart library unavailable";
                }

                if (span) {
                    span.textContent =
                        "Check your internet connection or load Chart.js locally.";
                }
            }

            const canvas = shell.querySelector("canvas");

            if (canvas) {
                canvas.hidden = true;
            }
        });
    } else {
        renderCharts("weekly");
    }

    // -------------------------
    // INITIALIZE INCIDENT FILTER
    // -------------------------

    filterIncidents();

});

// Admin settings are stored locally in this browser for this coursework build.
document.addEventListener("DOMContentLoaded", () => {
    const key = "sirsAdminSettings";
    const ids = ["autoArchiveDays", "anonymityElevated", "highSlaHours", "mediumSlaHours", "lowSlaDays"];
    const saveButton = document.getElementById("saveAdminSettings");
    const message = document.getElementById("settingsSaveMessage");
    const controls = Object.fromEntries(ids.map(id => [id, document.getElementById(id)]));
    if (ids.some(id => !controls[id]) || !saveButton || !message) return;
    const defaults = {autoArchiveDays:"90", anonymityElevated:true, highSlaHours:"12", mediumSlaHours:"48", lowSlaDays:"5"};
    try {
        const saved = JSON.parse(localStorage.getItem(key) || "{}");
        const values = {...defaults, ...saved};
        ids.forEach(id => {
            if (controls[id].type === "checkbox") controls[id].checked = values[id] !== false;
            else controls[id].value = String(values[id]);
        });
    } catch (_) { /* Use default values if browser storage is unavailable. */ }
    saveButton.addEventListener("click", () => {
        const values = {};
        ids.forEach(id => values[id] = controls[id].type === "checkbox" ? controls[id].checked : controls[id].value);
        try {
            localStorage.setItem(key, JSON.stringify(values));
            message.textContent = "Settings saved in this browser.";
        } catch (_) {
            message.textContent = "Unable to save settings in this browser.";
        }
    });
});
