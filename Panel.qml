import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model

Panel {
  id: root
  moduleName: "io.github.grynov.cert-wifi"
  ipcTarget: "io.github.grynov.cert-wifi"

  property var anchorItem: null
  property var hostWidget: null
  readonly property var barIdentity: hostWidget || root

  property var profiles: []
  property string activeSsid: ""
  property var discoveredFiles: []
  property var discoveredNetworks: []
  property string selectedFilePath: ""
  property string passwordText: ""
  property string ssidText: ""
  property string domainText: ""
  property string identityText: ""
  property string anonIdentityText: ""
  property string statusMessage: ""
  property string errorMessage: ""
  property bool busy: false
  property bool showAdvanced: false
  property var inspectedCert: null
  property string currentTab: "profiles"

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color dim: Qt.darker(foreground, 1.5)
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  readonly property string helperPath: {
    var url = Qt.resolvedUrl("backend/cert-helper.sh").toString()
    return decodeURIComponent(url.replace(/^file:\/\//, ""))
  }

  readonly property var activeProfile: {
    for (var i = 0; i < root.profiles.length; i++) {
      if (root.profiles[i].isConnected === true || (root.activeSsid && root.profiles[i].ssid === root.activeSsid)) {
        return root.profiles[i]
      }
    }
    return null
  }

  readonly property string heroTitle: {
    if (root.activeProfile) return "Connected to " + root.activeProfile.ssid
    if (root.profiles.length > 0) return "Certificate Wi-Fi"
    return "Enterprise Certificate Wi-Fi"
  }

  readonly property string heroSubtitle: {
    if (root.activeProfile) {
      return "Certificate valid: " + Model.formatDaysRemaining(root.activeProfile.daysRemaining)
    }
    if (root.profiles.length > 0) {
      return root.profiles.length + " certificate profile" + (root.profiles.length > 1 ? "s" : "") + " installed"
    }
    return "Connect to any 802.1X network using TLS certificates"
  }

  function clearInputFields() {
    root.selectedFilePath = ""
    root.passwordText = ""
    root.ssidText = ""
    root.domainText = ""
    root.identityText = ""
    root.anonIdentityText = ""
    root.inspectedCert = null
    root.showAdvanced = false
  }

  function open(tab) {
    if (tab === "new" || tab === "profiles") root.currentTab = tab
    root.controller.show()
    root.refresh()
    if (scrollArea && scrollArea.ScrollBar && scrollArea.ScrollBar.vertical) {
      scrollArea.ScrollBar.vertical.position = 0
    }
  }

  function openNew() {
    root.currentTab = "new"
    root.open()
  }

  function openProfiles() {
    root.currentTab = "profiles"
    root.open()
  }

  function close() {
    root.controller.hide()
    root.statusMessage = ""
    root.errorMessage = ""
  }

  function toggle() {
    if (root.opened) root.close()
    else root.open()
  }

  function switchPanel(direction) {
    if (root.bar && typeof root.bar.switchPanelFrom === "function") {
      return root.bar.switchPanelFrom(root.hostWidget || root, direction)
    }
    return false
  }

  function refresh() {
    if (!statusProc.running) statusProc.running = true
    if (!discoverProc.running) discoverProc.running = true
  }

  function runInspect(filePath) {
    if (!filePath || filePath.trim() === "") return
    if (inspectProc.running) inspectProc.running = false
    inspectProc.secret = root.passwordText
    inspectProc.command = [root.helperPath, "inspect", "--file", filePath.trim()]
    inspectProc.running = true
  }

  function runInstall() {
    if (root.selectedFilePath === "") {
      root.errorMessage = "Please select or provide a certificate bundle (.p12 / .pfx)."
      return
    }
    if (root.ssidText.trim() === "") {
      root.errorMessage = "Please specify the Wi-Fi network SSID."
      return
    }

    if (installProc.running) installProc.running = false

    root.busy = true
    root.statusMessage = "Extracting certificate and configuring network profile…"
    root.errorMessage = ""

    installProc.secret = root.passwordText
    var cmd = [
      root.helperPath,
      "install",
      "--file", root.selectedFilePath,
      "--ssid", root.ssidText.trim(),
      "--backend", "auto"
    ]
    if (root.domainText.trim() !== "") {
      cmd.push("--domain", root.domainText.trim())
    }
    if (root.identityText.trim() !== "") {
      cmd.push("--identity", root.identityText.trim())
    }
    if (root.anonIdentityText.trim() !== "") {
      cmd.push("--anonymous-identity", root.anonIdentityText.trim())
    }
    installProc.command = cmd
    installProc.running = true
  }

  function connectProfile(id, ssid) {
    if (connectProc.running) connectProc.running = false
    root.busy = true
    root.statusMessage = "Connecting to " + ssid + "…"
    root.errorMessage = ""
    connectProc.command = [root.helperPath, "connect", "--ssid", ssid, "--id", id]
    connectProc.running = true
  }

  function disconnectProfile(id, ssid) {
    if (disconnectProc.running) disconnectProc.running = false
    root.busy = true
    root.statusMessage = "Disconnecting from " + ssid + "…"
    root.errorMessage = ""
    disconnectProc.command = [root.helperPath, "disconnect", "--ssid", ssid, "--id", id]
    disconnectProc.running = true
  }

  function deleteProfile(id) {
    if (deleteProc.running) deleteProc.running = false
    root.busy = true
    root.statusMessage = "Removing profile…"
    root.errorMessage = ""
    deleteProc.command = [root.helperPath, "delete", "--id", id]
    deleteProc.running = true
  }

  Component.onCompleted: root.refresh()

  Timer {
    id: statusPollTimer
    interval: root.opened ? 4000 : 10000
    running: true
    repeat: true
    onTriggered: {
      if (!root.busy && !statusProc.running) {
        statusProc.running = true
      }
    }
  }

  // --- Backend Processes ---

  Process {
    id: statusProc
    command: [root.helperPath, "status"]
    stdout: SplitParser {
      onRead: function(line) {
        var res = Model.parseJson(line, null)
        if (res && res.success) {
          root.profiles = res.profiles || []
          root.activeSsid = res.activeSsid || ""
        }
      }
    }
  }

  Process {
    id: discoverProc
    command: [root.helperPath, "discover"]
    stdout: SplitParser {
      onRead: function(line) {
        var res = Model.parseJson(line, null)
        if (res && res.success) {
          root.discoveredFiles = res.files || []
          root.discoveredNetworks = res.networks || []
        }
      }
    }
  }

  Process {
    id: inspectProc
    property string secret: ""
    stdinEnabled: true
    onStarted: {
      write(secret + "\n")
      secret = ""
    }
    stdout: SplitParser {
      onRead: function(line) {
        var res = Model.parseJson(line, null)
        if (res && res.success) {
          root.inspectedCert = res
          if (res.suggestedSsid && res.suggestedSsid !== "" && root.ssidText === "") {
            root.ssidText = res.suggestedSsid
          }
          if (res.domain && res.domain !== "" && root.domainText === "") {
            root.domainText = res.domain
          } else if (res.identity && root.domainText === "") {
            var extractedDomain = Model.extractDomainFromIdentity(res.identity)
            if (extractedDomain !== "") root.domainText = extractedDomain
          }
          if (res.identity && res.identity !== "" && root.identityText === "") {
            root.identityText = res.identity
          }
          if (!res.hasCa && (root.domainText === "")) {
            root.showAdvanced = true
          }
          root.errorMessage = ""
        } else if (res && res.error) {
          root.inspectedCert = null
          root.errorMessage = res.error
        }
      }
    }
    stderr: SplitParser {
      onRead: function(line) {
        var res = Model.parseJson(line, null)
        if (res && res.error) {
          root.errorMessage = res.error
        } else if (line && line.trim() !== "") {
          root.errorMessage = line.trim()
        }
      }
    }
  }

  Process {
    id: installProc
    property string secret: ""
    stdinEnabled: true
    onStarted: {
      write(secret + "\n")
      secret = ""
    }
    stdout: SplitParser {
      onRead: function(line) {
        var res = Model.parseJson(line, null)
        if (res && res.success) {
          root.statusMessage = "Profile installed for " + res.ssid + " (" + res.daysRemaining + " days valid). Activating connection…"
          root.errorMessage = ""
          root.clearInputFields()
          root.currentTab = "profiles"
          root.refresh()
        } else if (res && res.error) {
          root.errorMessage = res.error
        }
      }
    }
    stderr: SplitParser {
      onRead: function(line) {
        var res = Model.parseJson(line, null)
        if (res && res.error) {
          root.errorMessage = res.error
        } else if (line && line.trim() !== "") {
          root.errorMessage = line.trim()
        }
      }
    }
    onExited: function(exitCode, exitStatus) {
      root.busy = false
      if (exitCode !== 0 && root.errorMessage === "") {
        root.errorMessage = "Failed to configure network profile."
      }
      root.refresh()
    }
  }

  Process {
    id: connectProc
    stdout: SplitParser {
      onRead: function(line) {
        var res = Model.parseJson(line, null)
        if (res && res.success) {
          root.statusMessage = "Activated " + res.connected
          root.errorMessage = ""
        } else if (res && res.error) {
          root.errorMessage = res.error
        }
      }
    }
    stderr: SplitParser {
      onRead: function(line) {
        var res = Model.parseJson(line, null)
        if (res && res.error) {
          root.errorMessage = res.error
        } else if (line && line.trim() !== "") {
          root.errorMessage = line.trim()
        }
      }
    }
    onExited: function(exitCode) {
      root.busy = false
      if (exitCode !== 0 && root.errorMessage === "") {
        root.errorMessage = "Failed to activate network."
      }
      root.refresh()
    }
  }

  Process {
    id: disconnectProc
    onExited: function() {
      root.busy = false
      root.refresh()
    }
  }

  Process {
    id: deleteProc
    stdout: SplitParser {
      onRead: function(line) {
        var res = Model.parseJson(line, null)
        if (res && res.success) {
          root.statusMessage = "Profile removed."
          root.errorMessage = ""
        } else if (res && res.error) {
          root.errorMessage = res.error
        }
      }
    }
    stderr: SplitParser {
      onRead: function(line) {
        var res = Model.parseJson(line, null)
        if (res && res.error) {
          root.errorMessage = res.error
        } else if (line && line.trim() !== "") {
          root.errorMessage = line.trim()
        }
      }
    }
    onExited: function(exitCode) {
      root.busy = false
      if (exitCode !== 0 && root.errorMessage === "") {
        root.errorMessage = "Failed to remove profile."
      }
      root.refresh()
    }
  }

  readonly property bool isInputFocused: (ssidInput && ssidInput.activeFocus) ||
    (filePathInput && filePathInput.activeFocus) ||
    (passField && passField.activeFocus) ||
    (domainInput && domainInput.activeFocus) ||
    (identityInput && identityInput.activeFocus) ||
    (anonInput && anonInput.activeFocus)

  // --- UI Layout ---

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.barIdentity
    bar: root.bar
    open: root.opened
    centerOnBar: false
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(380))
    contentHeight: panel.fittedContentHeight(contentColumn.implicitHeight, Style.space(620))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      blocked: root.isInputFocused
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }

      ScrollView {
        id: scrollArea
        anchors.fill: parent
        clip: true
        contentWidth: availableWidth
        ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
        ScrollBar.vertical.policy: ScrollBar.AsNeeded

        Column {
          id: contentColumn
          width: scrollArea.availableWidth
          spacing: Style.space(12)

          // 1. Hero Header
          Item {
            width: parent.width
            implicitHeight: Math.max(heroIcon.implicitHeight, heroLabels.implicitHeight)

            Item {
              id: heroIcon
              anchors.left: parent.left
              anchors.verticalCenter: parent.verticalCenter
              implicitWidth: heroGlyph.implicitWidth
              implicitHeight: heroGlyph.implicitHeight

              Text {
                id: heroGlyph
                text: root.activeProfile ? "󰤪" : "󰌆"
                color: root.activeProfile ? Color.accent : root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.display
              }

              Text {
                visible: root.activeProfile !== null
                anchors.right: heroGlyph.right
                anchors.bottom: heroGlyph.bottom
                anchors.rightMargin: -Style.space(2)
                anchors.bottomMargin: -Style.space(1)
                text: "󰄬"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
              }
            }

            Column {
              id: heroLabels
              anchors.left: heroIcon.right
              anchors.leftMargin: Style.space(14)
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(2)

              Text {
                width: parent.width
                text: root.heroTitle
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.subtitle
                font.bold: true
                elide: Text.ElideRight
              }

              Text {
                width: parent.width
                text: root.heroSubtitle
                color: root.activeProfile ? Color.accent : root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                elide: Text.ElideRight
              }
            }
          }

          // Feedback Alerts
          Rectangle {
            visible: root.statusMessage !== ""
            width: parent.width
            implicitHeight: statusMsgText.implicitHeight + Style.space(12)
            color: Util.alpha(Color.accent, 0.15)
            radius: Style.cornerRadius
            border.color: Color.accent
            border.width: 1

            Text {
              id: statusMsgText
              anchors.fill: parent
              anchors.margins: Style.space(6)
              text: "󰄬 " + root.statusMessage
              color: Color.accent
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }
          }

          Rectangle {
            visible: root.errorMessage !== ""
            width: parent.width
            implicitHeight: errorMsgText.implicitHeight + Style.space(12)
            color: Util.alpha(Color.urgent, 0.15)
            radius: Style.cornerRadius
            border.color: Color.urgent
            border.width: 1

            Text {
              id: errorMsgText
              anchors.fill: parent
              anchors.margins: Style.space(6)
              text: "󰅖 " + root.errorMessage
              color: Color.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }
          }

          // Segmented Tab Switcher
          RowLayout {
            width: parent.width
            spacing: Style.space(8)

            Button {
              Layout.fillWidth: true
              text: "Existing Profiles" + (root.profiles.length > 0 ? " (" + root.profiles.length + ")" : "")
              iconText: "󰤪"
              active: root.currentTab === "profiles"
              selected: root.currentTab === "profiles"
              onClicked: root.currentTab = "profiles"
            }

            Button {
              Layout.fillWidth: true
              text: "New Connection"
              iconText: "󰐕"
              active: root.currentTab === "new"
              selected: root.currentTab === "new"
              onClicked: root.currentTab = "new"
            }
          }

          // ================= TAB 1: EXISTING PROFILES =================
          Column {
            visible: root.currentTab === "profiles"
            width: parent.width
            spacing: Style.space(10)

            PanelSeparator { foreground: root.foreground }

            PanelSectionHeader {
              text: "SAVED CERTIFICATE NETWORKS"
              foreground: root.foreground
            }

            Repeater {
              model: root.profiles

              Rectangle {
                id: profileCard
                width: parent.width
                implicitHeight: profileContent.implicitHeight + Style.space(16)
                color: modelData.isConnected === true
                  ? Util.alpha(Color.accent, 0.08)
                  : Util.alpha(root.foreground, 0.04)
                radius: Style.cornerRadius
                border.color: modelData.isConnected === true
                  ? Color.accent
                  : Util.alpha(root.foreground, 0.12)
                border.width: 1

                Column {
                  id: profileContent
                  anchors.fill: parent
                  anchors.margins: Style.space(8)
                  spacing: Style.space(6)

                  RowLayout {
                    width: parent.width

                    Text {
                      text: (modelData.isConnected === true ? "󰤪 " : "󰤨 ") + modelData.ssid
                      color: root.foreground
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.body
                      font.bold: true
                      Layout.fillWidth: true
                    }

                    Rectangle {
                      implicitWidth: badgeLabel.implicitWidth + Style.space(12)
                      implicitHeight: badgeLabel.implicitHeight + Style.space(4)
                      radius: Style.cornerRadius
                      color: modelData.isConnected === true
                        ? Color.accent
                        : (modelData.daysRemaining < 14 ? "#f59e0b" : Util.alpha(root.foreground, 0.15))

                      Text {
                        id: badgeLabel
                        anchors.centerIn: parent
                        text: Model.profileBadgeLabel(modelData)
                        color: modelData.isConnected === true ? Color.background : root.foreground
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        font.bold: true
                      }
                    }
                  }

                  Text {
                    width: parent.width
                    text: modelData.identity
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    elide: Text.ElideMiddle
                  }

                  Text {
                    width: parent.width
                    text: "Expires: " + Model.formatDate(modelData.notAfter) + (modelData.domain ? " · " + modelData.domain : "")
                    color: modelData.daysRemaining < 14 ? "#f59e0b" : root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                  }

                  RowLayout {
                    width: parent.width
                    spacing: Style.space(8)

                    Button {
                      Layout.fillWidth: true
                      text: modelData.isConnected === true ? "Disconnect" : "Connect"
                      iconText: modelData.isConnected === true ? "󰅖" : "󰌘"
                      active: modelData.isConnected === true
                      onClicked: {
                        if (modelData.isConnected === true) {
                          root.disconnectProfile(modelData.id, modelData.ssid)
                        } else {
                          root.connectProfile(modelData.id, modelData.ssid)
                        }
                      }
                    }

                    Button {
                      text: "Delete"
                      iconText: "󰆴"
                      onClicked: root.deleteProfile(modelData.id)
                    }
                  }
                }
              }
            }

            Rectangle {
              visible: root.profiles.length === 0
              width: parent.width
              implicitHeight: emptyCol.implicitHeight + Style.space(28)
              color: Util.alpha(root.foreground, 0.03)
              radius: Style.cornerRadius
              border.color: Util.alpha(root.foreground, 0.08)
              border.width: 1

              Column {
                id: emptyCol
                anchors.centerIn: parent
                spacing: Style.space(8)

                Text {
                  anchors.horizontalCenter: parent.horizontalCenter
                  text: "󰌆 No Saved Certificate Networks"
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                  font.bold: true
                }

                Text {
                  anchors.horizontalCenter: parent.horizontalCenter
                  text: "Import an 802.1X certificate to connect"
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  opacity: 0.8
                }

                Button {
                  anchors.horizontalCenter: parent.horizontalCenter
                  text: "Add Certificate Profile"
                  iconText: "󰐕"
                  active: true
                  selected: true
                  onClicked: root.currentTab = "new"
                }
              }
            }

            Button {
              visible: root.profiles.length > 0
              width: parent.width
              text: "Add Another Network"
              iconText: "󰐕"
              onClicked: root.currentTab = "new"
            }
          }

          // ================= TAB 2: NEW CONNECTION =================
          Column {
            visible: root.currentTab === "new"
            width: parent.width
            spacing: Style.space(10)

            PanelSeparator { foreground: root.foreground }

            PanelSectionHeader {
              text: "CONNECT WITH TLS CERTIFICATE"
              foreground: root.foreground
            }

            // Discovered / Suggested Networks (1-Click Selector)
            Column {
              visible: root.discoveredNetworks.length > 0
              width: parent.width
              spacing: Style.space(4)

              Text {
                text: "Select or Enter Network SSID:"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }

              Flow {
                width: parent.width
                spacing: Style.space(6)

                Repeater {
                  model: root.discoveredNetworks

                  Button {
                    visible: modelData.ssid && modelData.ssid !== ""
                    text: "󰤨 " + modelData.ssid
                    active: root.ssidText === modelData.ssid
                    fontSize: Style.font.caption
                    onClicked: {
                      root.ssidText = modelData.ssid
                    }
                  }
                }
              }
            }

            // SSID Manual Input
            Column {
              width: parent.width
              spacing: Style.space(4)

              Text {
                text: "Network SSID:"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }

              TextField {
                id: ssidInput
                width: parent.width
                text: root.ssidText
                placeholderText: "Network SSID (e.g. Corp-WiFi, Campus-Secure, eduroam)"
                onTextChanged: {
                  if (root.ssidText !== text) root.ssidText = text
                }
                Keys.onEscapePressed: root.close()
                onAccepted: if (root.selectedFilePath.trim() !== "") root.runInstall()
              }
            }

            // Auto-Discovered Certificate Bundles (1-Click Selector)
            Column {
              visible: root.discoveredFiles.length > 0
              width: parent.width
              spacing: Style.space(4)

              Text {
                text: "Discovered Certificate Files:"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }

              Flow {
                width: parent.width
                spacing: Style.space(6)

                Repeater {
                  model: root.discoveredFiles

                  Button {
                    text: "󰈔 " + modelData.name
                    active: root.selectedFilePath === modelData.path
                    fontSize: Style.font.caption
                    onClicked: {
                      root.selectedFilePath = modelData.path
                      root.runInspect(modelData.path)
                    }
                  }
                }
              }
            }

            // File Path Field
            Column {
              width: parent.width
              spacing: Style.space(4)

              Text {
                text: "Certificate Bundle Path (.p12 / .pfx)"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }

              TextField {
                id: filePathInput
                width: parent.width
                text: root.selectedFilePath
                placeholderText: "/path/to/certificate.p12"
                onTextChanged: {
                  if (root.selectedFilePath !== text) {
                    root.selectedFilePath = text
                  }
                }
                onEditingFinished: {
                  if (text.trim().length > 0) root.runInspect(text)
                }
                onAccepted: {
                  if (text.trim().length > 0) root.runInspect(text)
                }
                Keys.onEscapePressed: root.close()
              }
            }

            // Password Field
            Column {
              width: parent.width
              spacing: Style.space(4)

              Text {
                text: "Certificate Password (leave empty if none)"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }

              TextField {
                id: passField
                width: parent.width
                password: true
                text: root.passwordText
                placeholderText: "Decryption password"
                onTextChanged: {
                  if (root.passwordText !== text) root.passwordText = text
                }
                onAccepted: {
                  if (root.selectedFilePath.trim() !== "") root.runInspect(root.selectedFilePath)
                }
                Keys.onEscapePressed: root.close()
              }
            }

            // Live Certificate Preview Card
            Rectangle {
              visible: root.inspectedCert !== null
              width: parent.width
              implicitHeight: certPreviewCol.implicitHeight + Style.space(16)
              color: Util.alpha(Color.accent, 0.08)
              radius: Style.cornerRadius
              border.color: Util.alpha(Color.accent, 0.3)
              border.width: 1

              Column {
                id: certPreviewCol
                anchors.fill: parent
                anchors.margins: Style.space(8)
                spacing: Style.space(4)

                RowLayout {
                  width: parent.width

                  Text {
                    text: "󰄬 Certificate Decrypted"
                    color: Color.accent
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    font.bold: true
                    Layout.fillWidth: true
                  }

                  Rectangle {
                    implicitWidth: certBadgeText.implicitWidth + Style.space(8)
                    implicitHeight: certBadgeText.implicitHeight + Style.space(4)
                    radius: Style.cornerRadius
                    color: Color.accent

                    Text {
                      id: certBadgeText
                      anchors.centerIn: parent
                      text: root.inspectedCert ? root.inspectedCert.daysRemaining + "d valid" : ""
                      color: Color.background
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                      font.bold: true
                    }
                  }
                }

                Text {
                  visible: root.inspectedCert && root.inspectedCert.identity !== ""
                  width: parent.width
                  text: "Identity: " + (root.inspectedCert ? root.inspectedCert.identity : "")
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  elide: Text.ElideRight
                }

                Text {
                  visible: root.inspectedCert && root.inspectedCert.domain !== ""
                  width: parent.width
                  text: "Domain Match: " + (root.inspectedCert ? root.inspectedCert.domain : "")
                  color: Color.accent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  elide: Text.ElideRight
                }

                Text {
                  visible: root.inspectedCert !== null
                  width: parent.width
                  text: root.inspectedCert && root.inspectedCert.hasCa ? "CA: Embedded Enterprise CA Included" : "CA: System Trust Store (Public CAs)"
                  color: root.inspectedCert && root.inspectedCert.hasCa ? Color.accent : "#f59e0b"
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }

                Text {
                  visible: root.inspectedCert && root.inspectedCert.notAfter !== ""
                  width: parent.width
                  text: "Expires: " + (root.inspectedCert ? Model.formatDate(root.inspectedCert.notAfter) : "")
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }
              }
            }

            // MitM Protection Advisory
            Rectangle {
              visible: root.inspectedCert !== null && !root.inspectedCert.hasCa && (root.domainText === "")
              width: parent.width
              implicitHeight: mitmCol.implicitHeight + Style.space(12)
              color: Util.alpha("#f59e0b", 0.12)
              radius: Style.cornerRadius
              border.color: Util.alpha("#f59e0b", 0.5)
              border.width: 1

              Column {
                id: mitmCol
                anchors.fill: parent
                anchors.margins: Style.space(6)
                spacing: Style.space(2)

                Text {
                  width: parent.width
                  text: "⚠ MitM Protection Recommendation"
                  color: "#f59e0b"
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }

                Text {
                  width: parent.width
                  text: "No enterprise CA found in bundle. Specify a Server Domain Suffix Match in Advanced Settings below to protect against Rogue AP / Evil Twin attacks."
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.WordWrap
                  opacity: 0.9
                }
              }
            }

            // Advanced Options Toggle
            Button {
              text: root.showAdvanced ? "▲ Hide Advanced TLS Settings" : "▼ Show Advanced TLS Settings"
              fontSize: Style.font.caption
              onClicked: root.showAdvanced = !root.showAdvanced
            }

            // Advanced Settings Fields
            Column {
              visible: root.showAdvanced
              width: parent.width
              spacing: Style.space(8)

              Column {
                width: parent.width
                spacing: Style.space(4)

                Text {
                  text: "Server Domain Suffix Match (MitM Protection)"
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }

                TextField {
                  id: domainInput
                  width: parent.width
                  text: root.domainText
                  placeholderText: "e.g. radius.institution.edu, radius.company.com"
                  onTextChanged: {
                    if (root.domainText !== text) root.domainText = text
                  }
                  Keys.onEscapePressed: root.close()
                  onAccepted: root.runInstall()
                }
              }

              Column {
                width: parent.width
                spacing: Style.space(4)

                Text {
                  text: "Client Identity (auto-extracted from certificate if empty)"
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }

                TextField {
                  id: identityInput
                  width: parent.width
                  text: root.identityText
                  placeholderText: "e.g. user@domain.com"
                  onTextChanged: {
                    if (root.identityText !== text) root.identityText = text
                  }
                  Keys.onEscapePressed: root.close()
                  onAccepted: root.runInstall()
                }
              }

              Column {
                width: parent.width
                spacing: Style.space(4)

                Text {
                  text: "Anonymous Outer Identity (optional)"
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }

                TextField {
                  id: anonInput
                  width: parent.width
                  text: root.anonIdentityText
                  placeholderText: "e.g. anonymous@domain.com"
                  onTextChanged: {
                    if (root.anonIdentityText !== text) root.anonIdentityText = text
                  }
                  Keys.onEscapePressed: root.close()
                  onAccepted: root.runInstall()
                }
              }
            }

            // Action Button
            Button {
              width: parent.width
              text: root.busy ? "Configuring…" : "Install & Connect"
              iconText: root.busy ? "󰑓" : "󰌆"
              iconSpinning: root.busy
              enabled: !root.busy
              active: true
              selected: true
              onClicked: root.runInstall()
            }
          }
        }
      }
    }
  }
}
