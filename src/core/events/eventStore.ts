/**
 * PhishGuard Security Event Store
 * 
 * Manages bounded, in-memory & session-backed security events per tab.
 * Ensures the background service worker can reconstruct timelines and correlate
 * events without persisting any sensitive credentials or payload data.
 */

import { BaseSecurityEvent, ThreatSeverity } from './eventTypes';

export const MAX_EVENTS_PER_TAB = 50;

export class SecurityEventStore {
  private tabEvents: Map<number, BaseSecurityEvent[]> = new Map();

  /**
   * Records a security event for a specific browser tab.
   * Performs defensive input validation to prevent invalid entries.
   */
  public recordEvent(event: BaseSecurityEvent | null | undefined): void {
    if (!event || typeof event !== 'object' || typeof event.tabId !== 'number' || event.tabId <= 0) {
      return;
    }

    const tabId = event.tabId;
    if (!this.tabEvents.has(tabId)) {
      this.tabEvents.set(tabId, []);
    }

    const events = this.tabEvents.get(tabId)!;
    events.push(event);

    // Keep bounded history to avoid unbounded memory growth in long-running service workers
    if (events.length > MAX_EVENTS_PER_TAB) {
      events.shift();
    }
  }

  /**
   * Canonical alias for recordEvent to support addEvent callers across background listeners.
   */
  public addEvent(event: BaseSecurityEvent | null | undefined): void {
    this.recordEvent(event);
  }

  /**
   * Retrieves all recorded security events for a tab in chronological order.
   * Returns an immutable copy array.
   */
  public getTabEvents(tabId: number): BaseSecurityEvent[] {
    if (typeof tabId !== 'number' || tabId <= 0) {
      return [];
    }
    return [...(this.tabEvents.get(tabId) || [])];
  }

  /**
   * Cleans up events when a tab is closed or navigates to a new origin.
   */
  public clearTab(tabId: number): void {
    if (typeof tabId === 'number') {
      this.tabEvents.delete(tabId);
    }
  }

  /**
   * Clears all recorded events across all tabs.
   */
  public clearAll(): void {
    this.tabEvents.clear();
  }

  /**
   * Returns total count of stored events across all tabs or for a specific tab.
   */
  public getEventCount(tabId?: number): number {
    if (typeof tabId === 'number') {
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
  public getRecentEvents(limit: number = 20): BaseSecurityEvent[] {
    const allEvents: BaseSecurityEvent[] = [];
    for (const events of this.tabEvents.values()) {
      allEvents.push(...events);
    }
    return allEvents.sort((a, b) => b.timestamp - a.timestamp).slice(0, Math.max(1, limit));
  }

  /**
   * Returns whether any events of high or critical severity were recorded for this tab.
   */
  public hasHighSeverityEvents(tabId: number): boolean {
    if (typeof tabId !== 'number' || tabId <= 0) {
      return false;
    }
    const events = this.tabEvents.get(tabId) || [];
    return events.some(e => e.severity === 'HIGH' || e.severity === 'CRITICAL');
  }
}

// Global in-memory singleton for runtime usage in MV3 service worker
export const globalEventStore = new SecurityEventStore();
