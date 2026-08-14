(() => {
  "use strict";

  const search = document.getElementById("report-search");
  const filterButtons = Array.from(document.querySelectorAll(".filter-button"));
  const searchable = Array.from(document.querySelectorAll(".searchable"));
  let activeFilter = "all";

  const applyFilters = () => {
    const query = (search.value || "").trim().toLocaleLowerCase();
    searchable.forEach((item) => {
      const severity = item.dataset.severity || "";
      const kind = item.dataset.kind || "";
      const filterMatch =
        activeFilter === "all" ||
        activeFilter === severity ||
        (activeFilter === "coverage-gaps" && kind === "coverage-gap") ||
        (activeFilter === "endpoints" && kind === "endpoint");
      const textMatch = !query || item.textContent.toLocaleLowerCase().includes(query);
      item.classList.toggle("hidden", !(filterMatch && textMatch));
    });
  };

  filterButtons.forEach((button) => {
    button.addEventListener("click", () => {
      activeFilter = button.dataset.filter;
      filterButtons.forEach((item) => item.classList.toggle("active", item === button));
      applyFilters();
    });
  });
  search.addEventListener("input", applyFilters);

  document.getElementById("theme-toggle").addEventListener("click", () => {
    const root = document.documentElement;
    root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
  });

  const details = Array.from(document.querySelectorAll("details"));
  let previousState = [];
  window.addEventListener("beforeprint", () => {
    previousState = details.map((item) => item.open);
    details.forEach((item) => {
      item.open = true;
      item.classList.add("print-open");
    });
  });
  window.addEventListener("afterprint", () => {
    details.forEach((item, index) => {
      item.open = previousState[index];
      item.classList.remove("print-open");
    });
  });
  document.getElementById("print-report").addEventListener("click", () => window.print());

  document.querySelectorAll("table.sortable").forEach((table) => {
    table.querySelectorAll(":scope > thead th").forEach((heading, column) => {
      heading.tabIndex = 0;
      heading.title = "Sort table by this column";
      const sort = () => {
        const body = table.querySelector(":scope > tbody");
        if (!body) return;
        const ascending = heading.dataset.direction !== "asc";
        const rows = Array.from(body.rows);
        rows.sort((left, right) => {
          const a = (left.cells[column]?.textContent || "").trim();
          const b = (right.cells[column]?.textContent || "").trim();
          return a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" }) * (ascending ? 1 : -1);
        });
        rows.forEach((row) => body.append(row));
        heading.dataset.direction = ascending ? "asc" : "desc";
      };
      heading.addEventListener("click", sort);
      heading.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") sort();
      });
    });
  });

  document.querySelectorAll(".inventory-controls").forEach((controls) => {
    const searchInput = controls.querySelector("[data-inventory-search]");
    const statusSelect = controls.querySelector("[data-inventory-status]");
    const table = controls.nextElementSibling?.querySelector(".inventory-table");
    if (!searchInput || !statusSelect || !table) return;
    const rows = Array.from(table.querySelectorAll("[data-inventory-row]"));
    const filterInventory = () => {
      const query = searchInput.value.trim().toLocaleLowerCase();
      const status = statusSelect.value;
      rows.forEach((row) => {
        const textMatch = !query || row.textContent.toLocaleLowerCase().includes(query);
        const statusMatch = !status || row.dataset.securityStatus === status;
        row.classList.toggle("hidden", !(textMatch && statusMatch));
      });
    };
    searchInput.addEventListener("input", filterInventory);
    statusSelect.addEventListener("change", filterInventory);
  });

  const wireFilter = (buttonSelector, rowSelector, valueAttribute, matcher) => {
    const buttons = Array.from(document.querySelectorAll(buttonSelector));
    const rows = Array.from(document.querySelectorAll(rowSelector));
    buttons.forEach((button) => {
      button.addEventListener("click", () => {
        const value = button.dataset[valueAttribute];
        buttons.forEach((item) => item.classList.toggle("active", item === button));
        rows.forEach((row) => row.classList.toggle("hidden", !matcher(row, value)));
      });
    });
  };

  wireFilter(".vulnerability-filter", "[data-vulnerability-row]", "vulnerabilityFilter", (row, value) => {
    if (value === "all") return true;
    if (value === "confirmed") return Number(row.dataset.confirmed) > 0;
    if (value === "possible") return Number(row.dataset.possible) > 0;
    if (value === "critical") return Number(row.dataset.critical) > 0;
    if (value === "high") return Number(row.dataset.high) > 0;
    return value === "known-exploited" && Number(row.dataset.kev) > 0;
  });
  wireFilter(".matrix-filter", "[data-matrix-row]", "matrixFilter", (row, value) => {
    if (value === "all-software") return true;
    if (value === "vulnerable") return row.dataset.vulnerable === "1";
    if (value === "end-of-support") return row.dataset.eol === "1";
    if (value === "remote-access") return row.dataset.remote === "1";
    return value === "only-differences" && row.dataset.different === "1";
  });
  wireFilter(".framework-filter", "[data-framework-row]", "frameworkFilter", (row, value) => {
    if (value === "all") return true;
    return (row.dataset.framework || "").includes(value);
  });

  const copyButton = document.getElementById("copy-remediation");
  const copyStatus = document.getElementById("copy-status");
  const remediationMarkdown = () => Array.from(document.querySelectorAll(".remediation-row"))
    .map((row) => {
      const priority = row.cells[0]?.textContent.trim() || "";
      const affected = row.dataset.endpoints.split("|").filter(Boolean).join(", ");
      return `## ${priority} - ${row.dataset.action}\nAffected: ${affected}\nReason: ${row.dataset.reason}\nVerification: ${row.dataset.verification}`;
    }).join("\n\n");
  const fallbackCopy = (value) => {
    const area = document.createElement("textarea");
    area.value = value;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.append(area);
    area.select();
    const copied = document.execCommand("copy");
    area.remove();
    return copied;
  };
  copyButton.addEventListener("click", async () => {
    const markdown = remediationMarkdown();
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(markdown);
      } else if (!fallbackCopy(markdown)) {
        throw new Error("Clipboard is unavailable");
      }
      copyStatus.textContent = "Remediation list copied as Markdown.";
    } catch (_error) {
      copyStatus.textContent = "Clipboard access was blocked by the browser.";
    }
  });

  const openFragment = () => {
    if (!location.hash) return;
    let target;
    try {
      target = document.querySelector(location.hash);
    } catch (_error) {
      return;
    }
    if (!target) return;
    if (target.tagName === "DETAILS") target.open = true;
    const parent = target.closest("details");
    if (parent) parent.open = true;
  };
  window.addEventListener("hashchange", openFragment);
  openFragment();

  const navigation = Array.from(document.querySelectorAll(".report-nav a"));
  const sections = navigation
    .map((link) => document.querySelector(link.getAttribute("href")))
    .filter(Boolean);
  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver((entries) => {
      entries.filter((entry) => entry.isIntersecting).forEach((entry) => {
        navigation.forEach((link) => {
          link.classList.toggle("active", link.getAttribute("href") === `#${entry.target.id}`);
        });
      });
    }, { rootMargin: "-15% 0px -70% 0px" });
    sections.forEach((section) => observer.observe(section));
  }
})();
