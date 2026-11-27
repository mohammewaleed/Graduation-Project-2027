/**
 * Accessible, high-contrast modern custom dropdown enhancer for all `.form-select` elements.
 * Uses a body-mounted fixed portal so popovers are never clipped by `.card` or modal overflow.
 * Strictly CSP & XSS safe: zero innerHTML, zero inline handlers.
 */

const ENHANCED_ATTR = "data-cselect-enhanced";

let activeDropdown = null;

function createChevronSvg() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "cselect-chevron");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "16");
  svg.setAttribute("height", "16");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2.2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  const poly = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
  poly.setAttribute("points", "6 9 12 15 18 9");
  svg.appendChild(poly);
  return svg;
}

function createCheckSvg() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "cselect-check");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "15");
  svg.setAttribute("height", "15");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2.6");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  const poly = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
  poly.setAttribute("points", "20 6 9 17 4 12");
  svg.appendChild(poly);
  return svg;
}

function closeActiveDropdown(restoreFocus = false) {
  if (!activeDropdown) return;
  const inst = activeDropdown;
  activeDropdown = null;
  inst.close(restoreFocus);
}

class CustomSelectInstance {
  /** @param {HTMLSelectElement} selectEl */
  constructor(selectEl) {
    this.select = selectEl;
    this.isOpen = false;
    this.focusedIndex = -1;

    this.wrapper = document.createElement("div");
    this.wrapper.className = "cselect";

    // Preserve explicit layout styles set on the original <select> (width/flex/minWidth/maxWidth)
    const inlineStyle = selectEl.style;
    if (inlineStyle.width) this.wrapper.style.width = inlineStyle.width;
    if (inlineStyle.minWidth) this.wrapper.style.minWidth = inlineStyle.minWidth;
    if (inlineStyle.maxWidth) this.wrapper.style.maxWidth = inlineStyle.maxWidth;
    if (inlineStyle.flex) this.wrapper.style.flex = inlineStyle.flex;

    this.trigger = document.createElement("button");
    this.trigger.type = "button";
    this.trigger.className = "cselect-trigger";
    this.trigger.setAttribute("aria-haspopup", "listbox");
    this.trigger.setAttribute("aria-expanded", "false");
    const ariaLabel = selectEl.getAttribute("aria-label");
    if (ariaLabel) this.trigger.setAttribute("aria-label", ariaLabel);

    this.valueSpan = document.createElement("span");
    this.valueSpan.className = "cselect-value";
    this.triggerBadge = document.createElement("span");
    this.triggerBadge.className = "cselect-badge hidden";
    this.trigger.appendChild(this.valueSpan);
    this.trigger.appendChild(this.triggerBadge);
    this.trigger.appendChild(createChevronSvg());

    this.menu = document.createElement("div");
    this.menu.className = "cselect-menu";
    this.menu.setAttribute("role", "listbox");

    // Insert wrapper right before <select>, move <select> inside hidden visually
    selectEl.parentNode.insertBefore(this.wrapper, selectEl);
    this.wrapper.appendChild(selectEl);
    this.wrapper.appendChild(this.trigger);

    selectEl.classList.add("cselect-native");
    selectEl.tabIndex = -1;
    selectEl.setAttribute("aria-hidden", "true");
    selectEl.setAttribute(ENHANCED_ATTR, "1");

    // Clicking an associated <label for="..."> should focus & toggle our trigger
    if (selectEl.id) {
      const label = document.querySelector(`label[for="${CSS.escape(selectEl.id)}"]`);
      if (label && !label.hasAttribute("data-cselect-label")) {
        label.setAttribute("data-cselect-label", "1");
        label.addEventListener("click", (e) => {
          if (!document.body.contains(this.trigger)) return;
          e.preventDefault();
          this.trigger.focus();
          this.toggle();
        });
      }
    }

    this.trigger.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (this.select.disabled) return;
      this.toggle();
    });

    this.trigger.addEventListener("keydown", (e) => {
      if (this.select.disabled) return;
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        if (!this.isOpen) {
          this.open();
        } else {
          this._moveFocus(e.key === "ArrowDown" ? 1 : -1);
        }
      } else if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        if (this.isOpen && this.focusedIndex >= 0) {
          this._selectByIndex(this.focusedIndex);
        } else {
          this.toggle();
        }
      } else if (e.key === "Escape" && this.isOpen) {
        e.preventDefault();
        closeActiveDropdown(true);
      }
    });

    this.select.addEventListener("change", () => this.syncFromSelect());

    // Watch dynamic <option> mutations or disabled state changes on the underlying <select>
    this._optionObserver = new MutationObserver(() => {
      this.syncFromSelect();
      if (this.isOpen) this._buildMenuItems();
    });
    this._optionObserver.observe(this.select, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["disabled", "selected", "value", "data-sub", "data-badge"],
    });

    this.syncFromSelect();
  }

  syncFromSelect() {
    const selectedOpt = this.select.options[this.select.selectedIndex] || this.select.options[0];
    this.valueSpan.textContent = selectedOpt ? selectedOpt.textContent || "" : "";
    const badgeText = selectedOpt ? selectedOpt.getAttribute("data-badge") || "" : "";
    if (badgeText) {
      this.triggerBadge.textContent = badgeText;
      this.triggerBadge.classList.remove("hidden");
    } else {
      this.triggerBadge.textContent = "";
      this.triggerBadge.classList.add("hidden");
    }
    this.trigger.disabled = Boolean(this.select.disabled);
    this.wrapper.classList.toggle("is-disabled", Boolean(this.select.disabled));
  }

  toggle() {
    if (this.isOpen) {
      closeActiveDropdown(true);
    } else {
      this.open();
    }
  }

  open() {
    if (activeDropdown && activeDropdown !== this) {
      closeActiveDropdown(false);
    }
    this.isOpen = true;
    activeDropdown = this;
    this.wrapper.classList.add("is-open");
    this.trigger.setAttribute("aria-expanded", "true");

    this._buildMenuItems();
    document.body.appendChild(this.menu);
    this._positionMenu();

    // Scroll selected option into view inside menu
    const selectedEl = this.menu.querySelector(".cselect-option.is-selected");
    if (selectedEl && typeof selectedEl.scrollIntoView === "function") {
      selectedEl.scrollIntoView({ block: "nearest" });
    }
  }

  close(restoreFocus = false) {
    this.isOpen = false;
    this.focusedIndex = -1;
    this.wrapper.classList.remove("is-open");
    this.trigger.setAttribute("aria-expanded", "false");
    if (this.menu.parentNode) {
      this.menu.parentNode.removeChild(this.menu);
    }
    if (restoreFocus && document.body.contains(this.trigger)) {
      this.trigger.focus();
    }
  }

  _buildMenuItems() {
    while (this.menu.firstChild) {
      this.menu.removeChild(this.menu.firstChild);
    }

    const options = Array.from(this.select.options);
    this.focusedIndex = this.select.selectedIndex;

    options.forEach((opt, idx) => {
      const isSelected = idx === this.select.selectedIndex;
      const itemBtn = document.createElement("button");
      itemBtn.type = "button";
      itemBtn.setAttribute("role", "option");
      itemBtn.setAttribute("aria-selected", isSelected ? "true" : "false");
      itemBtn.className = `cselect-option${isSelected ? " is-selected" : ""}`;
      itemBtn.disabled = Boolean(opt.disabled);

      const badgeText = opt.getAttribute("data-badge") || "";
      const subText = opt.getAttribute("data-sub") || "";

      const contentCol = document.createElement("div");
      contentCol.className = "cselect-option-content";

      const topLine = document.createElement("div");
      topLine.className = "cselect-option-top";

      const labelSpan = document.createElement("span");
      labelSpan.className = "cselect-option-label";
      labelSpan.textContent = opt.textContent || "";
      topLine.appendChild(labelSpan);

      if (badgeText) {
        const badgeEl = document.createElement("span");
        badgeEl.className = "cselect-badge";
        badgeEl.textContent = badgeText;
        topLine.appendChild(badgeEl);
      }

      contentCol.appendChild(topLine);

      if (subText) {
        const subEl = document.createElement("div");
        subEl.className = "cselect-option-sub";
        subEl.textContent = subText;
        contentCol.appendChild(subEl);
      }

      itemBtn.appendChild(contentCol);

      if (isSelected) {
        itemBtn.appendChild(createCheckSvg());
      }

      itemBtn.addEventListener("mouseenter", () => {
        this.focusedIndex = idx;
        this._highlightFocused();
      });

      itemBtn.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (opt.disabled) return;
        this._selectByIndex(idx);
      });

      this.menu.appendChild(itemBtn);
    });
  }

  _highlightFocused() {
    const items = this.menu.querySelectorAll(".cselect-option");
    items.forEach((el, idx) => {
      el.classList.toggle("is-focused", idx === this.focusedIndex);
    });
  }

  _moveFocus(delta) {
    const count = this.select.options.length;
    if (count === 0) return;
    let next = this.focusedIndex;
    for (let step = 0; step < count; step += 1) {
      next = (next + delta + count) % count;
      if (!this.select.options[next].disabled) break;
    }
    this.focusedIndex = next;
    this._highlightFocused();
    const activeItem = this.menu.children[next];
    if (activeItem && typeof activeItem.scrollIntoView === "function") {
      activeItem.scrollIntoView({ block: "nearest" });
    }
  }

  _selectByIndex(idx) {
    if (idx < 0 || idx >= this.select.options.length) return;
    const changed = this.select.selectedIndex !== idx;
    this.select.selectedIndex = idx;
    this.syncFromSelect();
    closeActiveDropdown(true);
    if (changed) {
      this.select.dispatchEvent(new Event("change", { bubbles: true }));
    }
  }

  _positionMenu() {
    const rect = this.trigger.getBoundingClientRect();
    const viewportW = window.innerWidth;
    const viewportH = window.innerHeight;
    const gap = 6;
    const maxMenuH = 300;

    const menuWidth = Math.max(rect.width, 200);
    const left = Math.min(Math.max(8, rect.left), Math.max(8, viewportW - menuWidth - 8));

    this.menu.style.width = `${menuWidth}px`;
    this.menu.style.left = `${left}px`;

    const spaceBelow = viewportH - rect.bottom - gap - 10;
    const spaceAbove = rect.top - gap - 10;
    const openUpward = spaceBelow < 180 && spaceAbove > spaceBelow;

    if (openUpward) {
      const avail = Math.min(maxMenuH, Math.max(120, spaceAbove));
      this.menu.style.maxHeight = `${avail}px`;
      this.menu.style.top = "auto";
      this.menu.style.bottom = `${viewportH - rect.top + gap}px`;
      this.menu.classList.add("is-upward");
    } else {
      const avail = Math.min(maxMenuH, Math.max(120, spaceBelow));
      this.menu.style.maxHeight = `${avail}px`;
      this.menu.style.bottom = "auto";
      this.menu.style.top = `${rect.bottom + gap}px`;
      this.menu.classList.remove("is-upward");
    }
  }
}

export function enhanceAllSelects(root = document) {
  const selects = root.querySelectorAll(`select.form-select:not([${ENHANCED_ATTR}])`);
  selects.forEach((sel) => {
    if (sel.parentNode) {
      new CustomSelectInstance(sel);
    }
  });
}

let initialized = false;

/**
 * Activate automatic custom-dropdown enhancement for all current and future `.form-select` elements.
 */
export function initModernSelects() {
  if (initialized) {
    enhanceAllSelects(document);
    return;
  }
  initialized = true;
  enhanceAllSelects(document);

  document.addEventListener("click", (e) => {
    if (!activeDropdown) return;
    if (
      !activeDropdown.wrapper.contains(e.target) &&
      !activeDropdown.menu.contains(e.target)
    ) {
      closeActiveDropdown(false);
    }
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && activeDropdown) {
      e.preventDefault();
      closeActiveDropdown(true);
    }
  });

  window.addEventListener("resize", () => {
    if (activeDropdown) activeDropdown._positionMenu();
  });

  window.addEventListener(
    "scroll",
    (e) => {
      if (!activeDropdown) return;
      if (activeDropdown.menu.contains(e.target)) return;
      activeDropdown._positionMenu();
    },
    true,
  );

  const domObserver = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.addedNodes.length > 0) {
        enhanceAllSelects(document);
        break;
      }
    }
  });
  domObserver.observe(document.body, { childList: true, subtree: true });
}
