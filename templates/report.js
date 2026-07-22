(() => {
  const filters = document.querySelector("[data-compliance-filters]");
  if (!filters) {
    return;
  }

  const controls = Array.from(filters.querySelectorAll("select[data-filter]"));
  const rows = Array.from(document.querySelectorAll(".compliance-control-row"));

  const applyFilters = () => {
    const selected = Object.fromEntries(
      controls.map((control) => [control.dataset.filter, control.value])
    );

    rows.forEach((row) => {
      const frameworkMatches =
        !selected.framework || row.dataset.framework === selected.framework;
      const statusMatches =
        !selected.status || row.dataset.status === selected.status;
      const scopeMatches =
        !selected.scope || (row.dataset.scope || "").split(" ").includes(selected.scope);

      row.hidden = !(frameworkMatches && statusMatches && scopeMatches);
    });
  };

  controls.forEach((control) => control.addEventListener("change", applyFilters));
})();

(() => {
  const filters = document.querySelector("[data-framework-pack-filters]");
  if (!filters) {
    return;
  }

  const selector = filters.querySelector("select[data-filter='view']");
  const rows = Array.from(document.querySelectorAll(".framework-pack-row"));
  const matches = (row, view) => {
    if (!view) return true;
    if (view === "failed") return row.dataset.status === "NOT_SATISFIED";
    if (view === "partial") return row.dataset.status === "PARTIALLY_SATISFIED";
    if (view === "not-assessable") return row.dataset.status === "NOT_ASSESSABLE";
    if (view === "unmapped") return row.dataset.unmapped === "true";
    if (view === "manual") return row.dataset.manual === "true";
    if (view === "provisional") return row.dataset.provisional === "true";
    return true;
  };

  selector.addEventListener("change", () => {
    rows.forEach((row) => {
      row.hidden = !matches(row, selector.value);
    });
  });
})();
