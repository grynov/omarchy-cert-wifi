function parseJson(raw, fallback) {
  try {
    if (!raw) return fallback !== undefined ? fallback : null;
    var parsed = JSON.parse(String(raw).trim());
    return parsed !== null && parsed !== undefined ? parsed : (fallback !== undefined ? fallback : null);
  } catch (e) {
    return fallback !== undefined ? fallback : null;
  }
}

function formatDaysRemaining(days) {
  var d = parseInt(days, 10);
  if (isNaN(d) || d <= 0) return "Expired";
  if (d === 1) return "1 day remaining";
  if (d < 30) return d + " days remaining";
  if (d < 365) return d + " days (" + Math.round(d / 30) + " mo)";
  var years = (d / 365).toFixed(1);
  return d + " days (" + years + " yr)";
}

function formatDate(dateStr) {
  if (!dateStr) return "";
  try {
    var d = new Date(dateStr);
    if (isNaN(d.getTime())) return String(dateStr);
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  } catch (e) {
    return String(dateStr);
  }
}

function profileHealth(profile) {
  if (!profile) return "unknown";
  var days = Number(profile.daysRemaining || 0);
  var isExpired = profile.isExpired === true || days <= 0;
  var isConnected = profile.isConnected === true;

  if (isExpired) return "expired";
  if (isConnected) return "connected";
  if (days < 14) return "warning";
  return "healthy";
}

function profileBadgeLabel(profile) {
  if (!profile) return "";
  var days = Number(profile.daysRemaining || 0);
  if (profile.isConnected === true) return "Active";
  if (profile.isExpired === true || days <= 0) return "Expired";
  if (days < 14) return days + "d left";
  return days + "d valid";
}

function barTooltip(profiles, activeSsid) {
  var list = profiles instanceof Array ? profiles : [];
  if (list.length === 0) {
    return "Certificate Wi-Fi · No certificate profile installed";
  }

  var connectedProfile = null;
  for (var i = 0; i < list.length; i++) {
    if (list[i].isConnected === true || (activeSsid && list[i].ssid === activeSsid)) {
      connectedProfile = list[i];
      break;
    }
  }

  if (connectedProfile) {
    var days = Number(connectedProfile.daysRemaining || 0);
    var validity = days > 0 ? days + " days left" : "Expired";
    return "Certificate Wi-Fi · Connected to " + connectedProfile.ssid + " (" + validity + ")";
  }

  return "Certificate Wi-Fi · " + list.length + " profile" + (list.length > 1 ? "s" : "") + " configured";
}

function barIconState(profiles, activeSsid) {
  var list = profiles instanceof Array ? profiles : [];
  if (list.length === 0) return { icon: "󰌆", state: "idle", badge: "" };

  var connected = false;
  var hasWarning = false;
  var hasExpired = false;
  var minDays = 99999;

  for (var i = 0; i < list.length; i++) {
    var p = list[i];
    var days = Number(p.daysRemaining || 0);
    if (p.isConnected === true || (activeSsid && p.ssid === activeSsid)) {
      connected = true;
    }
    if (p.isExpired === true || days <= 0) {
      hasExpired = true;
    } else if (days < 14) {
      hasWarning = true;
    }
    if (days < minDays) minDays = days;
  }

  if (hasExpired && connected) return { icon: "󰤫", state: "urgent", badge: "!" };
  if (hasWarning && connected) return { icon: "󰤫", state: "warning", badge: "!" };
  if (connected) return { icon: "󰤪", state: "connected", badge: "" };
  if (hasWarning) return { icon: "󰌆", state: "warning", badge: "!" };
  if (hasExpired) return { icon: "󰌆", state: "dimmed", badge: "×" };
  return { icon: "󰌆", state: "healthy", badge: "" };
}

function extractDomainFromIdentity(identity) {
  var id = String(identity || "").trim();
  var atIdx = id.lastIndexOf("@");
  if (atIdx === -1) return "";
  var domain = id.substring(atIdx + 1).trim();
  // Strip trailing quotes, slashes, semicolons, or dots
  domain = domain.replace(/[\/'"\\;\s]+$/g, "").replace(/^\.+|\.+$/g, "");
  // Easyroam PCA realms (e.g. easyroam-pca.uni-xxx.de) are client identities, not RADIUS server domains
  if (/^easyroam-pca\./i.test(domain) || /^easyroam\./i.test(domain) || /easyroam/i.test(domain)) {
    return "easyroam.eduroam.de";
  }
  return domain;
}

if (typeof module !== "undefined") {
  module.exports = {
    parseJson: parseJson,
    formatDaysRemaining: formatDaysRemaining,
    formatDate: formatDate,
    profileHealth: profileHealth,
    profileBadgeLabel: profileBadgeLabel,
    barTooltip: barTooltip,
    barIconState: barIconState,
    extractDomainFromIdentity: extractDomainFromIdentity
  };
}
