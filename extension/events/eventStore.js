const MAX_EVENTS_PER_TAB = 50;
class SecurityEventStore {
  constructor() {
    this.tabEvents = /* @__PURE__ */ new Map();
  }
  /**
   * Records a security event for a specific browser tab.
   * Performs defensive input validation to prevent invalid entries.
   */
  recordEvent(event) {
    if (!event || typeof event !== "object" || typeof event.tabId !== "number" || event.tabId <= 0) {
      return;
    }
    const tabId = event.tabId;
    if (!this.tabEvents.has(tabId)) {
      this.tabEvents.set(tabId, []);
    }
    const events = this.tabEvents.get(tabId);
    events.push(event);
    if (events.length > MAX_EVENTS_PER_TAB) {
      events.shift();
    }
  }
  /**
   * Canonical alias for recordEvent to support addEvent callers across background listeners.
   */
  addEvent(event) {
    this.recordEvent(event);
  }
  /**
   * Retrieves all recorded security events for a tab in chronological order.
   * Returns an immutable copy array.
   */
  getTabEvents(tabId) {
    if (typeof tabId !== "number" || tabId <= 0) {
      return [];
    }
    return [...this.tabEvents.get(tabId) || []];
  }
  /**
   * Cleans up events when a tab is closed or navigates to a new origin.
   */
  clearTab(tabId) {
    if (typeof tabId === "number") {
      this.tabEvents.delete(tabId);
    }
  }
  /**
   * Clears all recorded events across all tabs.
   */
  clearAll() {
    this.tabEvents.clear();
  }
  /**
   * Returns total count of stored events across all tabs or for a specific tab.
   */
  getEventCount(tabId) {
    if (typeof tabId === "number") {
      return (this.tabEvents.get(tabId) || []).length;
    }
    let count = 0;
    for (const events of this.tabEvents.values()) {
      count += events.length;
    }
    return count;
  }
  /**
   * Returns the most recent events across all active tabs in reverse chronological order.
   */
  getRecentEvents(limit = 20) {
    const allEvents = [];
    for (const events of this.tabEvents.values()) {
      allEvents.push(...events);
    }
    return allEvents.sort((a, b) => b.timestamp - a.timestamp).slice(0, Math.max(1, limit));
  }
  /**
   * Returns whether any events of high or critical severity were recorded for this tab.
   */
  hasHighSeverityEvents(tabId) {
    if (typeof tabId !== "number" || tabId <= 0) {
      return false;
    }
    const events = this.tabEvents.get(tabId) || [];
    return events.some((e) => e.severity === "HIGH" || e.severity === "CRITICAL");
  }
}
const globalEventStore = new SecurityEventStore();
export {
  MAX_EVENTS_PER_TAB,
  SecurityEventStore,
  globalEventStore
};
