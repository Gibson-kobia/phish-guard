/**
 * PhishGuard Security Events & Event Store Regression Test Suite
 * 
 * Verifies:
 * 1. Event creation boundary normalization (Navigation, Form, Page, Network, Download).
 * 2. Event Store contract: addEvent(), recordEvent(), getTabEvents(), clearTab(), clearAll(), getRecentEvents().
 * 3. Bounded FIFO eviction (MAX_EVENTS_PER_TAB = 50).
 * 4. Multi-tab isolation and session-safe lifecycle.
 * 5. End-to-end event retrieval and multi-signal behavioral correlation.
 */

import { createNavigationSecurityEvent } from '../events/navigationEvents';
import { createDownloadSecurityEvent } from '../events/downloadEvents';
import { createFormSecurityEvent } from '../events/formEvents';
import { createPageBrandingEvent } from '../events/pageEvents';
import { createNetworkSecurityEvent } from '../events/networkEvents';
import { SecurityEventStore, globalEventStore, MAX_EVENTS_PER_TAB } from '../events/eventStore';
import { correlateSecurityEvents } from '../events/eventCorrelator';

export function runEventRegressionTests(): { passed: number; failed: number; errors: string[] } {
  let passed = 0;
  let failed = 0;
  const errors: string[] = [];

  function assert(condition: boolean, testName: string, detail?: string) {
    if (condition) {
      passed++;
    } else {
      failed++;
      errors.push(`FAIL: ${testName}${detail ? ` (${detail})` : ''}`);
    }
  }

  // -------------------------------------------------------------
  // PART 1: NAVIGATION & DOWNLOAD EVENT BOUNDARY REGRESSIONS
  // -------------------------------------------------------------

  // 1. Exact production crash scenario: tabId passed as first arg with hopsList
  try {
    const ev1 = createNavigationSecurityEvent(42 as any, ['https://example.com/login']);
    assert(ev1 !== null, 'Regression 1: tabId number with hopsList returns valid event');
    assert(ev1?.tabId === 42, 'Regression 1: tabId is preserved correctly', `Got: ${ev1?.tabId}`);
    assert(ev1?.pageUrl === 'https://example.com/login', 'Regression 1: pageUrl extracted from hopsList', `Got: ${ev1?.pageUrl}`);
    assert(ev1?.pageOrigin === 'https://example.com', 'Regression 1: origin extracted properly', `Got: ${ev1?.pageOrigin}`);
  } catch (err: any) {
    failed++;
    errors.push(`FAIL: Regression 1 threw error: ${err?.message}`);
  }

  // 2. Undefined / null hop input
  try {
    const evNull = createNavigationSecurityEvent(null as any);
    assert(evNull === null, 'Regression 2: null input safely returns null without throwing');

    const evUndef = createNavigationSecurityEvent(undefined as any);
    assert(evUndef === null, 'Regression 2: undefined input safely returns null without throwing');
  } catch (err: any) {
    failed++;
    errors.push(`FAIL: Regression 2 threw error: ${err?.message}`);
  }

  // 3. Empty object or missing url property
  try {
    const evEmptyObj = createNavigationSecurityEvent({ tabId: 10 } as any);
    assert(evEmptyObj === null, 'Regression 3: object without url returns null safely');
  } catch (err: any) {
    failed++;
    errors.push(`FAIL: Regression 3 threw error: ${err?.message}`);
  }

  // 4. Object with null/undefined url but valid hopsList
  try {
    const evWithHops = createNavigationSecurityEvent({ tabId: 10 } as any, ['https://bank-login.com/auth']);
    assert(evWithHops !== null, 'Regression 4: fallback to hopsList when hop.url is undefined');
    assert(evWithHops?.pageUrl === 'https://bank-login.com/auth', 'Regression 4: pageUrl matches hopsList');
  } catch (err: any) {
    failed++;
    errors.push(`FAIL: Regression 4 threw error: ${err?.message}`);
  }

  // 5. Special Chrome internal schemes (chrome://, chrome-extension://, about:blank)
  try {
    const evChrome = createNavigationSecurityEvent({ tabId: 1, url: 'chrome://extensions/' });
    assert(evChrome !== null, 'Regression 5: chrome:// scheme handled');
    assert(evChrome?.severity === 'SAFE', 'Regression 5: chrome:// is SAFE severity');

    const evExt = createNavigationSecurityEvent({ tabId: 1, url: 'chrome-extension://kmgfmahgckfklffdilfghlhakfjjkghm/popup.html' });
    assert(evExt !== null, 'Regression 5: chrome-extension:// scheme handled');
    assert(evExt?.severity === 'SAFE', 'Regression 5: chrome-extension:// is SAFE severity');

    const evAbout = createNavigationSecurityEvent({ tabId: 1, url: 'about:blank' });
    assert(evAbout !== null, 'Regression 5: about:blank handled');
    assert(evAbout?.severity === 'SAFE', 'Regression 5: about:blank is SAFE severity');
  } catch (err: any) {
    failed++;
    errors.push(`FAIL: Regression 5 threw error: ${err?.message}`);
  }

  // 6. Multi-hop redirect trampoline via URL shortener
  try {
    const evShortener = createNavigationSecurityEvent(
      { tabId: 5, url: 'https://vintedmarket.netlify.app/login' },
      ['https://bit.ly/3xYqz', 'https://tinyurl.com/a9x81', 'https://vintedmarket.netlify.app/login']
    );
    assert(evShortener !== null, 'Regression 6: shortener trampoline returns valid event');
    assert(evShortener?.severity === 'HIGH', 'Regression 6: multi-hop shortener triggers HIGH severity');
    assert(evShortener?.hasUrlShortener === true, 'Regression 6: hasUrlShortener is true');
    assert(evShortener?.redirectHopCount === 3, 'Regression 6: redirectHopCount is 3');
  } catch (err: any) {
    failed++;
    errors.push(`FAIL: Regression 6 threw error: ${err?.message}`);
  }

  // 7. Defensive download event creation (both object and positional forms)
  try {
    const dlObj = createDownloadSecurityEvent({
      tabId: 3,
      downloadId: 101,
      url: 'https://malicious-drop.com/payload.exe',
      filename: 'invoice_update.exe',
      originUrl: 'https://malicious-drop.com/page',
      originRiskScore: 85
    });
    assert(dlObj !== null, 'Regression 7: download context object returns valid event');
    assert(dlObj?.isExecutable === true, 'Regression 7: isExecutable is true for .exe');
    assert(dlObj?.severity === 'CRITICAL', 'Regression 7: high risk executable download is CRITICAL');

    // Positional call signature compatibility
    const dlPos = createDownloadSecurityEvent(3, 'https://legit.com/home', 'https://legit.com/doc.pdf', 'doc.pdf', 0, 102);
    assert(dlPos !== null, 'Regression 7: positional download arguments handled safely');
    assert(dlPos?.isExecutable === false, 'Regression 7: .pdf is not executable');
    assert(dlPos?.severity === 'LOW', 'Regression 7: safe download is LOW');
  } catch (err: any) {
    failed++;
    errors.push(`FAIL: Regression 7 threw error: ${err?.message}`);
  }

  // -------------------------------------------------------------
  // PART 2: EVENT STORE CONTRACT & ADDEVENT / RECORDEVENT VERIFICATION
  // -------------------------------------------------------------

  try {
    const store = new SecurityEventStore();

    // 8. Verify addEvent exists and accepts navigation events
    assert(typeof store.addEvent === 'function', 'Regression 8: SecurityEventStore.addEvent is a function');
    assert(typeof globalEventStore.addEvent === 'function', 'Regression 8: globalEventStore.addEvent is a function');
    assert(typeof store.recordEvent === 'function', 'Regression 8: SecurityEventStore.recordEvent is a function');

    const navEvent = createNavigationSecurityEvent({ tabId: 100, url: 'https://vintedmarket.netlify.app/auth' });
    assert(navEvent !== null, 'Regression 8: valid navigation event created');

    store.addEvent(navEvent!);
    const stored = store.getTabEvents(100);
    assert(stored.length === 1, 'Regression 8: addEvent successfully stored event for tab 100', `Got: ${stored.length}`);
    assert(stored[0].type === 'NAVIGATION_COMMITTED', 'Regression 8: stored event matches NAVIGATION_COMMITTED type');
    assert(stored[0].pageUrl === 'https://vintedmarket.netlify.app/auth', 'Regression 8: stored event pageUrl matches');

    // 9. Global singleton instance verification
    globalEventStore.clearTab(100);
    globalEventStore.addEvent(navEvent!);
    const globalStored = globalEventStore.getTabEvents(100);
    assert(globalStored.length === 1, 'Regression 9: globalEventStore.addEvent successfully stores and retrieves event');
    assert(globalStored[0].tabId === 100, 'Regression 9: globalEventStore event tabId matches');
    globalEventStore.clearTab(100);

    // 10. Defensive handling of null / undefined / invalid inputs in addEvent
    store.addEvent(null);
    store.addEvent(undefined);
    store.addEvent({} as any);
    store.addEvent({ tabId: -1, pageUrl: '' } as any);
    assert(store.getTabEvents(100).length === 1, 'Regression 10: invalid events rejected gracefully without throwing');

    // 11. Multi-event insertion for single tab and chronological ordering
    const formEvent = createFormSecurityEvent(100, 'https://vintedmarket.netlify.app/auth', {
      hasPasswordField: true,
      has2FAField: true,
      action: 'https://attacker-stealer.xyz/collect',
      method: 'POST'
    });
    assert(formEvent !== null, 'Regression 11: form security event created');
    store.addEvent(formEvent!);

    const netEvent = createNetworkSecurityEvent(100, 'https://vintedmarket.netlify.app/auth', 'https://attacker-stealer.xyz/collect', 'POST', 'fetch', true);
    assert(netEvent !== null, 'Regression 11: network exfiltration event created');
    store.addEvent(netEvent!);

    const multiEvents = store.getTabEvents(100);
    assert(multiEvents.length === 3, 'Regression 11: 3 events stored in chronological order for tab 100', `Got: ${multiEvents.length}`);
    assert(multiEvents[0].type === 'NAVIGATION_COMMITTED', 'Regression 11: event 0 is navigation');
    assert(multiEvents[1].type === 'CROSS_ORIGIN_FORM_ACTION', 'Regression 11: event 1 is cross-origin form');
    assert(multiEvents[2].type === 'CREDENTIAL_SUBMISSION_PATTERN', 'Regression 11: event 2 is credential submission');

    // 12. Tab Isolation
    const tab200Events = store.getTabEvents(200);
    assert(tab200Events.length === 0, 'Regression 12: tab 200 has no events (per-tab isolation preserved)');

    store.addEvent(createNavigationSecurityEvent({ tabId: 200, url: 'https://legit-service.com/home' })!);
    assert(store.getTabEvents(200).length === 1, 'Regression 12: tab 200 has exactly 1 event');
    assert(store.getTabEvents(100).length === 3, 'Regression 12: tab 100 remains isolated with 3 events');

    // 13. High Severity Check
    assert(store.hasHighSeverityEvents(100) === true, 'Regression 13: tab 100 identified as having high severity events');
    assert(store.hasHighSeverityEvents(200) === false, 'Regression 13: tab 200 has no high severity events');

    // 14. Bounded History (MAX_EVENTS_PER_TAB = 50 FIFO eviction)
    const boundedStore = new SecurityEventStore();
    for (let i = 0; i < 60; i++) {
      boundedStore.addEvent({
        id: `ev_${i}`,
        timestamp: Date.now() + i,
        tabId: 300,
        pageUrl: `https://example.com/page_${i}`,
        pageOrigin: 'https://example.com',
        type: 'PAGE_LOADED',
        severity: 'LOW',
        title: `Page ${i}`,
        description: `Description ${i}`
      });
    }
    const boundedEvents = boundedStore.getTabEvents(300);
    assert(boundedEvents.length === MAX_EVENTS_PER_TAB, `Regression 14: events capped at ${MAX_EVENTS_PER_TAB}`, `Got: ${boundedEvents.length}`);
    assert(boundedEvents[0].id === 'ev_10', 'Regression 14: oldest events evicted in FIFO order', `First item: ${boundedEvents[0].id}`);
    assert(boundedEvents[boundedEvents.length - 1].id === 'ev_59', 'Regression 14: newest event is preserved', `Last item: ${boundedEvents[boundedEvents.length - 1].id}`);

    // 15. clearTab and clearAll
    store.clearTab(100);
    assert(store.getTabEvents(100).length === 0, 'Regression 15: clearTab(100) successfully wiped tab 100');
    assert(store.getTabEvents(200).length === 1, 'Regression 15: clearTab(100) did not affect tab 200');

    store.clearAll();
    assert(store.getEventCount() === 0, 'Regression 15: clearAll() wiped all events');
  } catch (err: any) {
    failed++;
    errors.push(`FAIL: Event Store Regressions threw error: ${err?.message}`);
  }

  // -------------------------------------------------------------
  // PART 3: END-TO-END EVENT RETRIEVAL & MULTI-SIGNAL CORRELATION
  // -------------------------------------------------------------

  try {
    const store = new SecurityEventStore();
    const tabId = 555;
    const phishingUrl = 'https://vintedmarket.netlify.app/auth/login';

    // Ingest Navigation Event
    const navEv = createNavigationSecurityEvent({ tabId, url: phishingUrl });
    store.addEvent(navEv);

    // Ingest Page Branding Event (Vinted on Netlify free hosting)
    const brandEv = createPageBrandingEvent(tabId, phishingUrl, 'Vinted UK - Login & Verification', ['Vinted Sign In']);
    store.addEvent(brandEv);

    // Ingest Credential Form Event
    const formEv = createFormSecurityEvent(tabId, phishingUrl, {
      hasPasswordField: true,
      has2FAField: true,
      action: 'https://steal-data.com/post',
      method: 'POST'
    });
    store.addEvent(formEv);

    // Ingest Cross-Origin Exfiltration Network Event
    const netEv = createNetworkSecurityEvent(tabId, phishingUrl, 'https://steal-data.com/post', 'POST', 'fetch', true);
    store.addEvent(netEv);

    // 16. Retrieve stored events and correlate (Object signature)
    const storedTimeline = store.getTabEvents(tabId);
    assert(storedTimeline.length === 4, 'Regression 16: exactly 4 events retrieved from store', `Got: ${storedTimeline.length}`);

    const correlationResultObj = correlateSecurityEvents({
      tabId,
      url: phishingUrl,
      domain: 'vintedmarket.netlify.app',
      events: storedTimeline
    });

    assert(correlationResultObj !== null, 'Regression 16: correlation succeeded with object signature');
    assert(correlationResultObj.verdict === 'DANGEROUS', 'Regression 16: correlated verdict is DANGEROUS', `Got: ${correlationResultObj.verdict}`);
    assert(correlationResultObj.score >= 85, 'Regression 16: correlated score escalated to >= 85', `Got: ${correlationResultObj.score}`);
    assert(correlationResultObj.evidence.length >= 2, 'Regression 16: multiple compound evidence items identified', `Got: ${correlationResultObj.evidence.length}`);

    // 17. Positional signature compatibility
    const correlationResultPos = correlateSecurityEvents(tabId, phishingUrl, storedTimeline);
    assert(correlationResultPos !== null, 'Regression 17: correlation succeeded with positional signature');
    assert(correlationResultPos.verdict === 'DANGEROUS', 'Regression 17: positional correlated verdict is DANGEROUS', `Got: ${correlationResultPos.verdict}`);
    assert(correlationResultPos.score === correlationResultObj.score, 'Regression 17: positional and object scores match identical evaluation');

    // 18. Legitimate Site Baseline Correlation
    const legitStore = new SecurityEventStore();
    const legitTabId = 777;
    const legitUrl = 'https://www.vinted.com/login';
    legitStore.addEvent(createNavigationSecurityEvent({ tabId: legitTabId, url: legitUrl }));
    legitStore.addEvent(createPageBrandingEvent(legitTabId, legitUrl, 'Vinted - Official Site', ['Vinted']));
    legitStore.addEvent(createFormSecurityEvent(legitTabId, legitUrl, {
      hasPasswordField: true,
      has2FAField: false,
      action: 'https://www.vinted.com/auth/login',
      method: 'POST'
    }));

    const legitTimeline = legitStore.getTabEvents(legitTabId);
    const legitCorrelated = correlateSecurityEvents({
      tabId: legitTabId,
      url: legitUrl,
      domain: 'vinted.com',
      events: legitTimeline
    });

    assert(legitCorrelated.verdict === 'SAFE', 'Regression 18: legitimate branded site correlates to SAFE verdict', `Got: ${legitCorrelated.verdict}`);
    assert(legitCorrelated.score <= 10, 'Regression 18: legitimate branded site score is <= 10', `Got: ${legitCorrelated.score}`);
  } catch (err: any) {
    failed++;
    errors.push(`FAIL: End-to-end event correlation regressions threw error: ${err?.message}`);
  }

  return { passed, failed, errors };
}
