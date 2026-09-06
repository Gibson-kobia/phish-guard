function formatEventTime(timestamp) {
  const d = new Date(timestamp);
  return d.toTimeString().split(" ")[0] || "";
}
function buildSecurityTimeline(params) {
  const events = [];
  const baseTime = params.timestamp;
  let offset = 0;
  const isHttps = params.url.startsWith("https:");
  events.push({
    id: `ev_nav_${baseTime}`,
    timestamp: baseTime + offset,
    timeString: formatEventTime(baseTime + offset),
    type: "NAVIGATION",
    title: "Page Navigation Observed",
    description: `Navigated to ${params.domain} (${isHttps ? "HTTPS Encrypted" : "Unencrypted HTTP"}).`,
    severity: isHttps ? "SAFE" : "HIGH"
  });
  offset += 40;
  if (params.redirectData && params.redirectData.hopCount > 1) {
    events.push({
      id: `ev_redir_${baseTime}`,
      timestamp: baseTime + offset,
      timeString: formatEventTime(baseTime + offset),
      type: "REDIRECT_CHAIN",
      title: `${params.redirectData.hopCount}-Hop Navigation Redirect`,
      description: `Observed redirect chain transition from ${params.redirectData.initialUrl.slice(0, 45)}...`,
      severity: params.redirectData.hasUrlShortener ? "MEDIUM" : "LOW"
    });
    offset += 30;
  }
  if (params.isAllowlisted) {
    events.push({
      id: `ev_rep_${baseTime}`,
      timestamp: baseTime + offset,
      timeString: formatEventTime(baseTime + offset),
      type: "DOMAIN_EVAL",
      title: "Trusted Domain Verified",
      description: `Domain is verified in local trusted allowlist catalog.`,
      severity: "SAFE"
    });
  } else if (params.isBlocklisted) {
    events.push({
      id: `ev_rep_${baseTime}`,
      timestamp: baseTime + offset,
      timeString: formatEventTime(baseTime + offset),
      type: "DOMAIN_EVAL",
      title: "Known Threat Match Flagged",
      description: `Domain matched local security threat intelligence database.`,
      severity: "CRITICAL"
    });
  } else {
    const typoSignals = params.signals.filter((s) => s.category === "TYPOSQUATTING");
    if (typoSignals.length > 0) {
      for (const sig of typoSignals) {
        events.push({
          id: `ev_typo_${sig.id}_${baseTime}`,
          timestamp: baseTime + offset,
          timeString: formatEventTime(baseTime + offset),
          type: "DOMAIN_EVAL",
          title: sig.title,
          description: sig.description,
          severity: sig.severity
        });
        offset += 20;
      }
    } else {
      events.push({
        id: `ev_domain_${baseTime}`,
        timestamp: baseTime + offset,
        timeString: formatEventTime(baseTime + offset),
        type: "DOMAIN_EVAL",
        title: "Domain Structure Inspected",
        description: `URL authority, entropy, and character mappings evaluated.`,
        severity: "SAFE"
      });
      offset += 30;
    }
  }
  if (params.formMeta) {
    if (params.formMeta.hasPasswordInput) {
      events.push({
        id: `ev_form_pwd_${baseTime}`,
        timestamp: baseTime + offset,
        timeString: formatEventTime(baseTime + offset),
        type: "FORM_SECURITY",
        title: "Credential Entry Form Detected",
        description: "Page contains active password/authentication input fields.",
        severity: "LOW"
      });
      offset += 20;
    }
    const crossOriginForms = (params.formMeta.suspiciousForms || []).filter((f) => f.isCrossOrigin && f.hasPasswordField);
    if (crossOriginForms.length > 0) {
      events.push({
        id: `ev_form_cross_${baseTime}`,
        timestamp: baseTime + offset,
        timeString: formatEventTime(baseTime + offset),
        type: "FORM_SECURITY",
        title: "Cross-Origin Form Target Flagged",
        description: `Form posts credentials to an external host: ${crossOriginForms[0].action.slice(0, 45)}...`,
        severity: "CRITICAL"
      });
      offset += 20;
    }
  }
  if (params.socialMeta && params.socialMeta.detectedPhrases.length > 0) {
    events.push({
      id: `ev_soc_${baseTime}`,
      timestamp: baseTime + offset,
      timeString: formatEventTime(baseTime + offset),
      type: "SOCIAL_ENGINEERING",
      title: "Coercive Social Engineering Cue",
      description: `Observed: ${params.socialMeta.detectedPhrases.slice(0, 2).join("; ")}`,
      severity: "HIGH"
    });
    offset += 20;
  }
  if (params.downloadContext) {
    events.push({
      id: `ev_down_${baseTime}`,
      timestamp: baseTime + offset,
      timeString: formatEventTime(baseTime + offset),
      type: "DOWNLOAD_CONTEXT",
      title: "File Download Initiated",
      description: `File "${params.downloadContext.filename}" download triggered from current tab context.`,
      severity: params.downloadContext.isDangerousOrigin ? "CRITICAL" : "MEDIUM"
    });
    offset += 20;
  }
  events.push({
    id: `ev_calc_${baseTime}`,
    timestamp: baseTime + offset,
    timeString: formatEventTime(baseTime + offset),
    type: "RISK_CALC",
    title: `Assessment Completed: ${params.score}/100 (${params.verdict.replace("_", " ")})`,
    description: params.score < 20 ? "Clean baseline security posture affirmed." : `${params.signals.length} security signal(s) evaluated.`,
    severity: params.severity
  });
  return events;
}
export {
  buildSecurityTimeline
};
