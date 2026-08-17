(() => {
  "use strict";

  const search = document.getElementById("report-search");
  const searchRoot = document.getElementById("main");
  const searchStatus = document.getElementById("search-status");
  const searchPrevious = document.getElementById("search-previous");
  const searchNext = document.getElementById("search-next");
  const searchClear = document.getElementById("search-clear");
  const filterButtons = Array.from(document.querySelectorAll(".filter-button"));
  const searchable = Array.from(document.querySelectorAll(".searchable"));
  let activeFilter = "all";
  let searchMatches = [];
  let activeSearchIndex = -1;
  let lastSearchQuery = "";
  let searchTimer = 0;
  const detailsOpenedBySearch = new Set();
  const elementsRevealedBySearch = new Set();

  const applyFindingFilters = () => {
    searchable.forEach((item) => {
      const severity = item.dataset.severity || "";
      const kind = item.dataset.kind || "";
      const filterMatch =
        activeFilter === "all" ||
        activeFilter === severity ||
        (activeFilter === "coverage-gaps" && kind === "coverage-gap") ||
        (activeFilter === "endpoints" && kind === "endpoint");
      item.classList.toggle("hidden", !filterMatch);
    });
  };

  filterButtons.forEach((button) => {
    button.addEventListener("click", () => {
      activeFilter = button.dataset.filter;
      filterButtons.forEach((item) => item.classList.toggle("active", item === button));
      applyFindingFilters();
    });
  });

  const restoreSearchContext = () => {
    detailsOpenedBySearch.forEach((item) => {
      item.open = false;
    });
    detailsOpenedBySearch.clear();
    elementsRevealedBySearch.forEach((item) => {
      item.classList.add("hidden");
    });
    elementsRevealedBySearch.clear();
  };

  const removeSearchHighlights = () => {
    const parents = new Set();
    document.querySelectorAll("mark[data-report-search-match]").forEach((mark) => {
      const parent = mark.parentNode;
      if (!parent) return;
      parent.replaceChild(document.createTextNode(mark.textContent || ""), mark);
      parents.add(parent);
    });
    parents.forEach((parent) => parent.normalize());
    searchMatches = [];
    activeSearchIndex = -1;
  };

  const updateSearchStatus = () => {
    const hasQuery = Boolean(lastSearchQuery);
    const hasMatches = searchMatches.length > 0;
    searchPrevious.disabled = !hasMatches;
    searchNext.disabled = !hasMatches;
    searchClear.disabled = !hasQuery;
    if (!hasQuery) {
      searchStatus.textContent = "No active search";
    } else if (!hasMatches) {
      searchStatus.textContent = "0 matches";
    } else {
      searchStatus.textContent = `${activeSearchIndex + 1} of ${searchMatches.length} matches`;
    }
  };

  const revealSearchMatch = (mark) => {
    let current = mark.parentElement;
    while (current && current !== searchRoot) {
      if (current.tagName === "DETAILS" && !current.open) {
        current.open = true;
        detailsOpenedBySearch.add(current);
      }
      if (current.classList.contains("hidden")) {
        current.classList.remove("hidden");
        elementsRevealedBySearch.add(current);
      }
      current = current.parentElement;
    }
  };

  const activateSearchMatch = (index) => {
    if (!searchMatches.length) {
      activeSearchIndex = -1;
      updateSearchStatus();
      return;
    }
    activeSearchIndex = (index + searchMatches.length) % searchMatches.length;
    searchMatches.forEach((mark, position) => {
      mark.classList.toggle("active", position === activeSearchIndex);
    });
    const active = searchMatches[activeSearchIndex];
    revealSearchMatch(active);
    active.scrollIntoView({ block: "center", behavior: "auto" });
    updateSearchStatus();
  };

  const searchableTextNodes = () => {
    const nodes = [];
    const walker = document.createTreeWalker(
      searchRoot,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode(node) {
          const parent = node.parentElement;
          if (!parent || !node.nodeValue || !node.nodeValue.trim()) {
            return NodeFilter.FILTER_REJECT;
          }
          if (parent.closest("script, style, noscript, button, input, select, option, textarea, [data-search-ignore]")) {
            return NodeFilter.FILTER_REJECT;
          }
          return NodeFilter.FILTER_ACCEPT;
        },
      },
    );
    let node = walker.nextNode();
    while (node) {
      nodes.push(node);
      node = walker.nextNode();
    }
    return nodes;
  };

  const highlightNodeMatches = (node, query) => {
    const value = node.nodeValue || "";
    const normalized = value.toLocaleLowerCase();
    let cursor = 0;
    let matchAt = normalized.indexOf(query, cursor);
    if (matchAt < 0) return;
    const fragment = document.createDocumentFragment();
    while (matchAt >= 0) {
      fragment.append(document.createTextNode(value.slice(cursor, matchAt)));
      const mark = document.createElement("mark");
      mark.dataset.reportSearchMatch = String(searchMatches.length);
      mark.textContent = value.slice(matchAt, matchAt + query.length);
      fragment.append(mark);
      searchMatches.push(mark);
      cursor = matchAt + query.length;
      matchAt = normalized.indexOf(query, cursor);
    }
    fragment.append(document.createTextNode(value.slice(cursor)));
    node.replaceWith(fragment);
  };

  const performReportSearch = () => {
    restoreSearchContext();
    removeSearchHighlights();
    lastSearchQuery = (search.value || "").trim().toLocaleLowerCase();
    if (!lastSearchQuery) {
      updateSearchStatus();
      return 0;
    }
    searchableTextNodes().forEach((node) => {
      highlightNodeMatches(node, lastSearchQuery);
    });
    if (searchMatches.length) activateSearchMatch(0);
    else updateSearchStatus();
    return searchMatches.length;
  };

  const clearReportSearch = () => {
    window.clearTimeout(searchTimer);
    search.value = "";
    performReportSearch();
  };

  search.addEventListener("input", () => {
    window.clearTimeout(searchTimer);
    searchTimer = window.setTimeout(performReportSearch, 120);
  });
  search.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      event.preventDefault();
      clearReportSearch();
      return;
    }
    if (event.key !== "Enter" || !search.value.trim()) return;
    event.preventDefault();
    window.clearTimeout(searchTimer);
    const query = search.value.trim().toLocaleLowerCase();
    if (query !== lastSearchQuery) performReportSearch();
    else activateSearchMatch(activeSearchIndex + (event.shiftKey ? -1 : 1));
  });
  searchPrevious.addEventListener("click", () => activateSearchMatch(activeSearchIndex - 1));
  searchNext.addEventListener("click", () => activateSearchMatch(activeSearchIndex + 1));
  searchClear.addEventListener("click", () => {
    clearReportSearch();
    search.focus();
  });

  window.CSAReportSearch = Object.freeze({
    search(query) {
      search.value = String(query || "");
      return performReportSearch();
    },
    clear: clearReportSearch,
    next() {
      activateSearchMatch(activeSearchIndex + 1);
      return activeSearchIndex;
    },
    previous() {
      activateSearchMatch(activeSearchIndex - 1);
      return activeSearchIndex;
    },
    state() {
      return {
        query: lastSearchQuery,
        matchCount: searchMatches.length,
        activeIndex: activeSearchIndex,
      };
    },
  });

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
