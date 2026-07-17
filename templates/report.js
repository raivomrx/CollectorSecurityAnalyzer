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
