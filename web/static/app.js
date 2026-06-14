// Vanilla JS helpers for the pcap-tool dashboard — no external dependencies.

function pcapToolPollStatus(statusUrl, resultsUrl) {
  var stateEl = document.getElementById("state");
  var logEl = document.getElementById("progress-log");
  var errEl = document.getElementById("error-box");

  function poll() {
    fetch(statusUrl)
      .then(function (r) { return r.json(); })
      .then(function (data) {
        stateEl.textContent = data.state;
        logEl.textContent = data.progress.join("\n");
        logEl.scrollTop = logEl.scrollHeight;

        if (data.state === "done") {
          window.location.href = resultsUrl;
          return;
        }
        if (data.state === "error") {
          errEl.style.display = "block";
          errEl.textContent = data.error;
          return;
        }
        setTimeout(poll, 1000);
      })
      .catch(function () {
        setTimeout(poll, 2000);
      });
  }
  poll();
}

// Client-side table filter: an <input data-filter-table="tableId"> filters
// rows of the given table by substring match (case-insensitive) across all
// cells.
document.addEventListener("DOMContentLoaded", function () {
  var filters = document.querySelectorAll("[data-filter-table]");
  filters.forEach(function (input) {
    var table = document.getElementById(input.getAttribute("data-filter-table"));
    if (!table) return;
    input.addEventListener("input", function () {
      var q = input.value.toLowerCase();
      var rows = table.querySelectorAll("tbody tr");
      rows.forEach(function (row) {
        row.style.display = row.textContent.toLowerCase().indexOf(q) === -1 ? "none" : "";
      });
    });
  });
});
