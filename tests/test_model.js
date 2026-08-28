const assert = require("assert");
const Model = require("../Model.js");

console.log("=== Running Model.js Unit Tests ===");

// 1. JSON Parsing
assert.strictEqual(Model.parseJson("", null), null);
assert.strictEqual(Model.parseJson("{ invalid", "fallback"), "fallback");
assert.deepStrictEqual(Model.parseJson('{"success":true}', null), { success: true });
// Oversized string (>1MB) should safely return fallback without parsing
const oversizedPayload = " ".repeat(1048577);
assert.strictEqual(Model.parseJson(oversizedPayload, "fallback"), "fallback");
console.log("PASS: parseJson (including oversized payload guard)");

// 2. barIconState
const emptyState = Model.barIconState([], "");
assert.deepStrictEqual(emptyState, { icon: "󰌆", state: "idle", badge: "" });

const connectedProfile = [{
  id: "eduroam",
  ssid: "eduroam",
  isConnected: true,
  daysRemaining: 729,
  isExpired: false
}];
const connectedState = Model.barIconState(connectedProfile, "eduroam");
assert.strictEqual(connectedState.icon, "󰤪");
assert.strictEqual(connectedState.state, "connected");
console.log("PASS: barIconState - connected returns wifi-lock icon");

const warningConnectedProfile = [{
  id: "eduroam",
  ssid: "eduroam",
  isConnected: true,
  daysRemaining: 5,
  isExpired: false
}];
const warningState = Model.barIconState(warningConnectedProfile, "eduroam");
assert.strictEqual(warningState.icon, "󰤫");
assert.strictEqual(warningState.state, "warning");
assert.strictEqual(warningState.badge, "!");
console.log("PASS: barIconState - warning connected");

const expiredConnectedProfile = [{
  id: "eduroam",
  ssid: "eduroam",
  isConnected: true,
  daysRemaining: 0,
  isExpired: true
}];
const expiredState = Model.barIconState(expiredConnectedProfile, "eduroam");
assert.strictEqual(expiredState.icon, "󰤫");
assert.strictEqual(expiredState.state, "urgent");
assert.strictEqual(expiredState.badge, "!");
console.log("PASS: barIconState - expired connected");

const idleSavedProfile = [{
  id: "corp",
  ssid: "corp",
  isConnected: false,
  daysRemaining: 100,
  isExpired: false
}];
const idleState = Model.barIconState(idleSavedProfile, "");
assert.strictEqual(idleState.icon, "󰌆");
assert.strictEqual(idleState.state, "healthy");
console.log("PASS: barIconState - disconnected profile returns key icon");

// 3. Tooltip
assert.strictEqual(Model.barTooltip([], ""), "Certificate Wi-Fi · No certificate profile installed");
assert.strictEqual(Model.barTooltip(connectedProfile, "eduroam"), "Certificate Wi-Fi · Connected to eduroam (729 days left)");
assert.strictEqual(Model.barTooltip(idleSavedProfile, ""), "Certificate Wi-Fi · 1 profile configured");
console.log("PASS: barTooltip");

// 4. Badges & Health
assert.strictEqual(Model.profileBadgeLabel({ isConnected: true, daysRemaining: 700 }), "Active");
assert.strictEqual(Model.profileBadgeLabel({ isConnected: false, daysRemaining: 5 }), "5d left");
assert.strictEqual(Model.profileBadgeLabel({ isConnected: false, daysRemaining: 0 }), "Expired");
console.log("PASS: profileBadgeLabel");

// 5. Domain Extraction
assert.strictEqual(Model.extractDomainFromIdentity("user@example.edu"), "example.edu");
assert.strictEqual(Model.extractDomainFromIdentity("user@example.edu/"), "example.edu");
assert.strictEqual(Model.extractDomainFromIdentity("user@example.edu."), "example.edu");
assert.strictEqual(Model.extractDomainFromIdentity("user@example.edu;"), "example.edu");
assert.strictEqual(Model.extractDomainFromIdentity("sample_user@easyroam-pca.example.edu"), "easyroam.eduroam.de");
assert.strictEqual(Model.extractDomainFromIdentity("user@easyroam.de"), "easyroam.eduroam.de");
assert.strictEqual(Model.extractDomainFromIdentity("no-domain"), "");
console.log("PASS: extractDomainFromIdentity");

console.log("===================================");
console.log("All Model.js tests passed!");
console.log("===================================");
