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
