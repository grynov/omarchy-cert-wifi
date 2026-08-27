import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model

BarWidget {
  id: root
  moduleName: "io.github.grynov.cert-wifi"

  function injectPanel() {
    var target = panelLoader.item
    if (!target) return
    if ("bar" in target) target.bar = root.bar
    if ("settings" in target) target.settings = root.settings
    if ("anchorItem" in target) target.anchorItem = button
    if ("hostWidget" in target) target.hostWidget = root
  }

  function togglePanel() {
    if (panelLoader.item && panelLoader.item.toggle) panelLoader.item.toggle()
  }

  function open() {
    if (panelLoader.item && panelLoader.item.open) panelLoader.item.open()
  }

  function openNew() {
    if (panelLoader.item && panelLoader.item.openNew) panelLoader.item.openNew()
  }

  function openProfiles() {
    if (panelLoader.item && panelLoader.item.openProfiles) panelLoader.item.openProfiles()
  }

  function close() {
    if (panelLoader.item && panelLoader.item.close) panelLoader.item.close()
  }

  function refresh() {
    if (panelLoader.item && panelLoader.item.refresh) panelLoader.item.refresh()
  }

  readonly property bool opened: panelLoader.item ? panelLoader.item.opened === true : false
  readonly property bool popoutSwitchClosing: panelLoader.item ? panelLoader.item.popoutSwitchClosing === true : false

  function closeForPopoutSwitch() {
    if (panelLoader.item) panelLoader.item.closeForPopoutSwitch()
  }

  readonly property var iconState: panelLoader.item && panelLoader.item.profiles
    ? Model.barIconState(panelLoader.item.profiles, panelLoader.item.activeSsid)
    : ({ icon: "󰌆", state: "idle", badge: "" })

  readonly property string tooltip: panelLoader.item && panelLoader.item.profiles
    ? Model.barTooltip(panelLoader.item.profiles, panelLoader.item.activeSsid)
    : "Certificate Wi-Fi"

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onBarChanged: injectPanel()
  onSettingsChanged: injectPanel()

  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml")
    onLoaded: {
      root.injectPanel()
      Qt.callLater(root.injectPanel)
      if (panelLoader.item && panelLoader.item.refresh) {
        panelLoader.item.refresh()
      }
    }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.iconState.icon
    active: root.iconState.state === "connected"
    dimmed: root.iconState.state === "idle" || root.iconState.state === "dimmed"
    tooltipText: root.tooltip

    iconComponent: Component {
      Item {
        OpticalGlyph {
          id: glyph
          anchors.fill: parent
          text: root.iconState.icon
          color: root.iconState.state === "connected"
            ? Color.accent
            : (root.iconState.state === "warning"
              ? "#f59e0b"
              : (root.iconState.state === "urgent"
                ? Color.urgent
                : button.foreground))
          fontFamily: button.fontFamily
          fontSize: button.fontSize
        }

        Text {
          visible: root.iconState.badge !== ""
          anchors.right: glyph.right
          anchors.bottom: glyph.bottom
          anchors.rightMargin: -Style.space(1)
          anchors.bottomMargin: -Style.space(1)
          text: root.iconState.badge
          color: root.iconState.state === "connected"
            ? Color.accent
            : (root.iconState.state === "warning" ? "#f59e0b" : Color.urgent)
          font.family: button.fontFamily
          font.pixelSize: Math.max(7, Math.round(button.fontSize * 0.45))
          font.bold: true
        }
      }
    }

    onPressed: function(mouseButton) {
      if (mouseButton === Qt.LeftButton) root.togglePanel()
      else if (mouseButton === Qt.MiddleButton) root.refresh()
    }
  }
}
