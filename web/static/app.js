// Vanilla JS helpers for the pcap-tool dashboard — no external dependencies.

function pcapToolPollStatus(statusUrl, resultsUrl) {
  var stateEl = document.getElementById("state");
  var logEl = document.getElementById("progress-log");
  var errEl = document.getElementById("error-box");
  var barEl = document.getElementById("progress-bar-fill");
  var pctEl = document.getElementById("progress-pct");
  var stageEl = document.getElementById("current-stage");

  var timer = null;
  var finished = false;

  function poll() {
    if (finished) return;
    // cache: "no-store" — some browsers will otherwise serve a stale
    // cached "running" response and never notice the job has finished.
    fetch(statusUrl, { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        stateEl.textContent = data.state;
        logEl.textContent = data.progress.join("\n");
        logEl.scrollTop = logEl.scrollHeight;

        if (barEl) barEl.style.width = data.progress_pct + "%";
        if (pctEl) pctEl.textContent = data.progress_pct;
        if (stageEl) stageEl.textContent = data.current_stage || "Starting…";

        if (data.state === "done") {
          finished = true;
          window.location.replace(resultsUrl);
          return;
        }
        if (data.state === "error") {
          finished = true;
          errEl.style.display = "block";
          errEl.textContent = data.error;
          return;
        }
        timer = setTimeout(poll, 1000);
      })
      .catch(function () {
        timer = setTimeout(poll, 2000);
      });
  }

  // Browsers throttle setTimeout heavily in background tabs, which can
  // leave this page stuck on "running" long after the job has actually
  // finished. Poll immediately whenever the tab becomes visible again.
  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "visible" && !finished) {
      if (timer) clearTimeout(timer);
      poll();
    }
  });

  poll();
}

// Makes a <table class="data"> sortable (click column headers) and
// filterable like a spreadsheet: each column header gets a "▾" button that
// opens an Excel-style checkbox list (search box + Select All + per-value
// checkboxes + OK/Cancel), in addition to an optional free-text
// [data-filter-table] search box.
function enhanceTable(table) {
  var thead = table.querySelector("thead");
  var tbody = table.querySelector("tbody");
  if (!thead || !tbody) return;
  var headerRow = thead.querySelector("tr");
  if (!headerRow) return;
  var ths = Array.prototype.slice.call(headerRow.children);
  var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr"));
  if (!rows.length) return;

  var NUMERIC_RE = /^-?[\d,.]+$/;
  var MAX_FILTER_OPTIONS = 500;
  var activeFilters = {}; // colIdx -> Set of allowed cell values

  // --- Optional free-text search box (data-filter-table="<table id>") ---
  var textInput = table.id
    ? document.querySelector('[data-filter-table="' + table.id + '"]')
    : null;

  function applyFilters() {
    var q = textInput ? textInput.value.toLowerCase() : "";
    rows.forEach(function (row) {
      var visible = !q || row.textContent.toLowerCase().indexOf(q) !== -1;
      if (visible) {
        for (var idx in activeFilters) {
          var c = row.children[idx];
          var v = c ? c.textContent.trim() : "";
          if (!activeFilters[idx].has(v)) { visible = false; break; }
        }
      }
      row.style.display = visible ? "" : "none";
    });
  }
  if (textInput) textInput.addEventListener("input", applyFilters);

  // --- Build an Excel-style checkbox filter popup for one column ---
  function buildFilterPopup(colIdx, uniqueValues, btn) {
    var popup = document.createElement("div");
    popup.className = "col-filter-popup";

    var search = document.createElement("input");
    search.type = "text";
    search.placeholder = "Search";
    popup.appendChild(search);

    var list = document.createElement("div");
    list.className = "col-filter-list";

    var selectAllLabel = document.createElement("label");
    var selectAllCb = document.createElement("input");
    selectAllCb.type = "checkbox";
    selectAllCb.checked = true;
    selectAllLabel.appendChild(selectAllCb);
    selectAllLabel.appendChild(document.createTextNode(" (Select All)"));
    list.appendChild(selectAllLabel);
    list.appendChild(document.createElement("hr"));

    var items = [];
    uniqueValues.forEach(function (v) {
      var label = document.createElement("label");
      var cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = !activeFilters[colIdx] || activeFilters[colIdx].has(v);
      var display = v === "" ? "(Blanks)" : (v.length > 40 ? v.slice(0, 40) + "…" : v);
      label.appendChild(cb);
      label.appendChild(document.createTextNode(" " + display));
      label.title = v;
      list.appendChild(label);
      items.push({ cb: cb, value: v, label: label });
    });
    popup.appendChild(list);

    var actions = document.createElement("div");
    actions.className = "col-filter-actions";
    var btnCancel = document.createElement("button");
    btnCancel.type = "button";
    btnCancel.className = "btn-cancel";
    btnCancel.textContent = "Cancel";
    var btnOk = document.createElement("button");
    btnOk.type = "button";
    btnOk.className = "btn-ok";
    btnOk.textContent = "OK";
    actions.appendChild(btnCancel);
    actions.appendChild(btnOk);
    popup.appendChild(actions);

    search.addEventListener("input", function () {
      var q = search.value.toLowerCase();
      items.forEach(function (item) {
        item.label.style.display = item.value.toLowerCase().indexOf(q) === -1 ? "none" : "";
      });
    });

    selectAllCb.addEventListener("change", function () {
      items.forEach(function (item) {
        if (item.label.style.display !== "none") item.cb.checked = selectAllCb.checked;
      });
    });

    list.addEventListener("change", function (e) {
      if (e.target === selectAllCb) return;
      selectAllCb.checked = items.every(function (item) { return item.cb.checked; });
    });

    btnCancel.addEventListener("click", function () {
      popup.classList.remove("open");
    });

    btnOk.addEventListener("click", function () {
      var checked = items.filter(function (item) { return item.cb.checked; })
                          .map(function (item) { return item.value; });
      if (checked.length === uniqueValues.length) {
        delete activeFilters[colIdx];
        btn.classList.remove("filter-active");
      } else {
        activeFilters[colIdx] = new Set(checked);
        btn.classList.add("filter-active");
      }
      popup.classList.remove("open");
      applyFilters();
    });

    popup.addEventListener("click", function (e) { e.stopPropagation(); });
    return popup;
  }

  ths.forEach(function (th, idx) {
    // Wrap existing header text so it stays clickable for sorting without
    // also triggering the filter button.
    var label = document.createElement("span");
    label.className = "th-label";
    label.textContent = th.textContent;
    th.textContent = "";
    th.appendChild(label);
    th.classList.add("sortable");

    label.addEventListener("click", function () {
      var asc = !th.classList.contains("sort-asc");
      ths.forEach(function (h) { h.classList.remove("sort-asc", "sort-desc"); });
      th.classList.add(asc ? "sort-asc" : "sort-desc");

      rows.sort(function (a, b) {
        var av = a.children[idx] ? a.children[idx].textContent.trim() : "";
        var bv = b.children[idx] ? b.children[idx].textContent.trim() : "";
        var cmp;
        if (NUMERIC_RE.test(av) && NUMERIC_RE.test(bv)) {
          cmp = parseFloat(av.replace(/,/g, "")) - parseFloat(bv.replace(/,/g, ""));
        } else {
          cmp = av.toLowerCase().localeCompare(bv.toLowerCase());
        }
        return asc ? cmp : -cmp;
      });
      rows.forEach(function (row) { tbody.appendChild(row); });
    });

    // Collect unique values for this column to build the filter dropdown.
    var values = {};
    rows.forEach(function (row) {
      var c = row.children[idx];
      values[c ? c.textContent.trim() : ""] = true;
    });
    var unique = Object.keys(values).sort();
    if (unique.length > 1 && unique.length <= MAX_FILTER_OPTIONS) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "col-filter-btn";
      btn.title = "Filter";
      btn.textContent = "▾";
      th.appendChild(btn);

      var popup = buildFilterPopup(idx, unique, btn);
      th.appendChild(popup);

      btn.addEventListener("click", function (e) {
        e.stopPropagation();
        var wasOpen = popup.classList.contains("open");
        document.querySelectorAll(".col-filter-popup.open").forEach(function (p) {
          p.classList.remove("open");
        });
        if (!wasOpen) popup.classList.add("open");
      });
    }
  });
}

// High-level "Network Map" — draws SVG lines between subnet boxes (weighted
// by total inter-subnet traffic) and between individual host chips (the
// busiest host-to-host conversations), using a log scale so both tiny and
// huge transfers remain visible on the same diagram.
function renderNetworkMap() {
  var wrap = document.querySelector(".network-map-wrap");
  var container = document.getElementById("network-map-boxes");
  var svg = document.getElementById("network-map-svg");
  var linksEl = document.getElementById("network-map-links");
  var nodeLinksEl = document.getElementById("network-map-node-links");
  if (!wrap || !container || !svg) return;

  var links = [];
  var nodeLinks = [];
  try {
    if (linksEl) links = JSON.parse(linksEl.textContent) || [];
    if (nodeLinksEl) nodeLinks = JSON.parse(nodeLinksEl.textContent) || [];
  } catch (e) {
    return;
  }
  if (!links.length && !nodeLinks.length) return;

  var boxes = {};
  container.querySelectorAll(".subnet-box").forEach(function (box) {
    boxes[box.getAttribute("data-subnet")] = box;
  });

  var chips = {};
  container.querySelectorAll(".node-chip[data-ip]").forEach(function (chip) {
    chips[chip.getAttribute("data-ip")] = chip;
  });

  var maxLinkBytes = links.reduce(function (m, l) { return Math.max(m, l.bytes); }, 1);
  var maxNodeBytes = nodeLinks.reduce(function (m, l) { return Math.max(m, l.bytes); }, 1);

  // Log scale so a 50-byte and a 50MB flow are both visible, while the
  // largest flow still stands out clearly.
  function logWidth(bytes, max, minW, maxW) {
    if (bytes <= 0) return minW;
    var t = Math.log(bytes + 1) / Math.log(max + 1);
    return minW + t * (maxW - minW);
  }

  function center(rect, wrapRect) {
    return {
      x: rect.left + rect.width / 2 - wrapRect.left,
      y: rect.top + rect.height / 2 - wrapRect.top,
    };
  }

  function drawLine(p1, p2, color, width, opacity, titleText) {
    var line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", p1.x);
    line.setAttribute("y1", p1.y);
    line.setAttribute("x2", p2.x);
    line.setAttribute("y2", p2.y);
    line.setAttribute("stroke", color);
    line.setAttribute("stroke-width", width);
    line.setAttribute("stroke-opacity", opacity);
    line.style.pointerEvents = "stroke";

    var title = document.createElementNS("http://www.w3.org/2000/svg", "title");
    title.textContent = titleText;
    line.appendChild(title);
    svg.appendChild(line);
  }

  function draw() {
    var wrapRect = wrap.getBoundingClientRect();
    svg.setAttribute("width", wrapRect.width);
    svg.setAttribute("height", wrapRect.height);
    while (svg.firstChild) svg.removeChild(svg.firstChild);

    links.forEach(function (link) {
      var a = boxes[link.a], b = boxes[link.b];
      if (!a || !b) return;
      var p1 = center(a.getBoundingClientRect(), wrapRect);
      var p2 = center(b.getBoundingClientRect(), wrapRect);
      var width = logWidth(link.bytes, maxLinkBytes, 1, 7);
      var title = link.a + " ↔ " + link.b + ": " +
        link.count + " connection(s), " + link.bytes.toLocaleString() + " bytes";
      drawLine(p1, p2, "#1f4e79", width, 0.35, title);
    });

    nodeLinks.forEach(function (link) {
      var a = chips[link.src], b = chips[link.dst];
      if (!a || !b) return;
      var p1 = center(a.getBoundingClientRect(), wrapRect);
      var p2 = center(b.getBoundingClientRect(), wrapRect);
      var width = logWidth(link.bytes, maxNodeBytes, 1, 5);
      var detail = [];
      if (link.protocols && link.protocols.length) detail.push(link.protocols.join(", "));
      if (link.ports && link.ports.length) detail.push("ports: " + link.ports.join(", "));
      var title = link.src + " → " + link.dst + ": " +
        link.count + " connection(s), " + link.bytes.toLocaleString() + " bytes" +
        (detail.length ? " (" + detail.join("; ") + ")" : "");
      drawLine(p1, p2, "#d9534f", width, 0.75, title);
    });
  }

  draw();
  window.addEventListener("resize", draw);
}

document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll("table.data").forEach(enhanceTable);

  // Close any open column-filter popup when clicking elsewhere on the page.
  document.addEventListener("click", function () {
    document.querySelectorAll(".col-filter-popup.open").forEach(function (p) {
      p.classList.remove("open");
    });
  });

  renderNetworkMap();

  // Highlight the sidebar link for whichever section is in view.
  var sidebar = document.querySelector(".sidebar-nav");
  if (sidebar && "IntersectionObserver" in window) {
    var links = {};
    sidebar.querySelectorAll("a[href^='#']").forEach(function (a) {
      links[a.getAttribute("href").slice(1)] = a;
    });
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        var link = links[entry.target.id];
        if (!link) return;
        if (entry.isIntersecting) {
          sidebar.querySelectorAll("a.active").forEach(function (a) { a.classList.remove("active"); });
          link.classList.add("active");
        }
      });
    }, { rootMargin: "-80px 0px -70% 0px" });
    Object.keys(links).forEach(function (id) {
      var section = document.getElementById(id);
      if (section) observer.observe(section);
    });
  }
});
