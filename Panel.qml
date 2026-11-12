import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// Hisense VIDAA TV remote in the Omarchy bar.
// Backend: scripts/vidaa.py — one singleton MQTT daemon (owned by the CLI, not
// by this QML), state published to a JSON file this widget watches, one-shot
// CLI calls per key press. Nothing here holds a socket or a long-lived child.
Panel {
  id: root

  moduleName: "meviusisback.hisense-tv"
  ipcTarget: "meviusisback.hisense-tv"
  // Explicit IPC handler: lets a keybinding (or a test) pop the remote
  // without a pointer. The Panel base's manageIpc registration is not used,
  // because a package-relative target must exist even before the first click.
  manageIpc: false

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color accent: Color.accent
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  // Last good state. Never replaced by a malformed/oversized document.
  property var tv: ({
    available: false, power: "unknown", statetype: "", volume: null, muted: false,
    source: "", channel: "", app: "", apps: [], sources: [], stale: true
  })
  property bool stateSeen: false
  property string statePath: ""
  property string errorCode: ""
  property bool busy: false

  readonly property bool barShowsStatus: String(root.setting("barDisplay", "Status")).toLowerCase() === "status"
  readonly property bool showVolume: root.setting("showVolume", true) === true
  readonly property bool tvOn: root.tv && root.tv.power === "on"
  readonly property bool paired: root.errorCode !== "pairing_required"
  readonly property var sources: (root.tv && root.tv.sources) || []
  readonly property var apps: (root.tv && root.tv.apps) || []

  readonly property string subtitle: {
    if (root.errorCode === "pairing_required") return "Not paired"
    if (root.errorCode === "tv_identity_changed") return "TV certificate changed"
    if (root.errorCode !== "") return root.errorCode
    if (!root.tvOn) return "Standby"
    if (root.tv.channel) return root.tv.channel
    if (root.tv.app) return root.tv.app
    return root.tv.source || "On"
  }

  function barText() {
    if (!root.barShowsStatus) return "\u25A3"
    var text = root.tvOn ? (root.tv.channel || root.tv.app || "TV") : "TV"
    if (root.showVolume && root.tvOn && typeof root.tv.volume === "number") text += " " + root.tv.volume
    return text
  }

  // argv-only spawns with a cleared environment; the CLI resolves everything
  // it needs to absolute paths itself, so nothing here depends on PATH.
  function cliArgv(args) {
    var argv = ["/usr/bin/env", "-i", "HOME=" + (Quickshell.env("HOME") || "")]
    for (const name of ["XDG_RUNTIME_DIR", "XDG_STATE_HOME", "XDG_CONFIG_HOME"]) {
      const value = Quickshell.env(name) || ""
      if (value !== "") argv.push(name + "=" + value)
    }
    // Absolute interpreter: the script's exec bit and shebang are not trusted,
    // and -I ignores PYTHON* variables and the user site directory.
    return argv.concat(["/usr/bin/python3", "-I", "-u",
                        Qt.resolvedUrl("scripts/vidaa.py").toString().replace(/^file:\/\//, "")], args)
  }

  function readState() {
    var parsed
    try {
      parsed = JSON.parse(stateView.text() || "")
    } catch (e) {
      return
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return
    var next = {
      available: parsed.available === true,
      power: typeof parsed.power === "string" ? parsed.power : "unknown",
      statetype: typeof parsed.statetype === "string" ? parsed.statetype : "",
      volume: typeof parsed.volume === "number" ? parsed.volume : null,
      muted: parsed.muted === true,
      source: typeof parsed.source === "string" ? parsed.source : "",
      channel: typeof parsed.channel === "string" ? parsed.channel : "",
      app: typeof parsed.app === "string" ? parsed.app : "",
      apps: [],
      sources: [],
      stale: parsed.stale === true
    }
    if (Array.isArray(parsed.apps)) {
      for (const entry of parsed.apps.slice(0, 30)) {
        if (entry && typeof entry.name === "string" && typeof entry.appId === "string"
            && entry.name.length <= 64 && /^[A-Za-z0-9._-]{1,16}$/.test(entry.appId))
          next.apps.push({ name: entry.name, appId: entry.appId })
      }
    }
    if (Array.isArray(parsed.sources)) {
      for (const entry of parsed.sources.slice(0, 16)) {
        if (entry && typeof entry.id === "string" && typeof entry.label === "string"
            && /^[A-Za-z0-9._-]{1,16}$/.test(entry.id))
          next.sources.push({ id: entry.id, label: entry.label.slice(0, 32) })
      }
    }
    var code = typeof parsed.code === "string" ? parsed.code : ""
    if (parsed.available !== true) code = code || "tv_unreachable"
    root.errorCode = code
    root.tv = next
    root.stateSeen = true
  }

  function run(args) {
    if (root.busy) return
    root.busy = true
    actionProc.command = root.cliArgv(args)
    actionProc.running = true
  }

  function key(name) { root.run(["key", name]) }
  function volume(action) { root.run(["vol", action]) }
  function setSource(id) { root.run(["source", id]) }
  function launch(appId) { root.run(["app", appId]) }
  function power() { root.run(["power"]) }

  // The CLI validates the runtime/state dirs and prints the path it will use;
  // this widget never derives one from an environment variable itself.
  Process {
    id: statePathProc
    command: root.cliArgv(["state-path"])
    running: true
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          const parsed = JSON.parse(text || "{}")
          if (parsed && parsed.ok === true && typeof parsed.path === "string"
              && parsed.path.startsWith("/")) root.statePath = parsed.path
        } catch (e) { /* keep trying via the fallback timer */ }
      }
    }
  }

  FileView {
    id: stateView
    path: root.statePath
    watchChanges: true
    printErrors: false
    onLoadFailed: { /* no state yet: keep the previous one */ }
    onLoaded: root.readState()
    onFileChanged: reload()
  }

  // Only while the daemon has never published a state file: re-ask for the
  // path and refresh, slowly. Inert in a normal session.
  Timer {
    interval: 30000
    repeat: true
    running: root.statePath === "" || !root.stateSeen
    onTriggered: {
      if (root.statePath === "") statePathProc.running = true
      root.run(["status"])
    }
  }

  Process {
    id: actionProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          const parsed = JSON.parse(text || "{}")
          if (parsed && parsed.ok === false && typeof parsed.code === "string")
            root.errorCode = parsed.code
          else if (parsed && parsed.ok === true)
            root.errorCode = ""
        } catch (e) { /* ignore: the state file is the source of truth */ }
      }
    }
    onExited: {
      root.busy = false
      stateView.reload()
    }
  }

  IpcHandler {
    target: "meviusisback.hisense-tv"
    function open(): void { root.open() }
    function close(): void { root.close() }
    function toggle(): void { root.toggle() }
    function refresh(): void { root.run(["status"]) }
  }

  // ---------------- bar button ----------------
  // WidgetButton, not BarIconButton: the status chip is a label, and
  // BarIconButton's fixed icon slot clips any text to one glyph.
  WidgetButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.barText()
    tooltipText: "Hisense TV: " + root.subtitle
    active: root.tvOn
    useActiveColor: true
    activeColor: root.accent
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.RightButton) root.run(["status"])
      else root.toggle()
    }
    onWheelMoved: function(delta) {
      if (!root.tvOn) return
      root.volume(delta > 0 ? "up" : "down")
    }
  }

  // ---------------- remote panel ----------------
  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    contentWidth: Style.space(360)
    // The content is a lazily built component: sizing it from an id inside
    // that component is not visible in this scope.
    contentHeight: Style.space(470)

    content: ColumnLayout {
      id: column
      spacing: Style.space(8)

      PanelSectionHeader {
        Layout.fillWidth: true
        text: "Hisense " + (root.tvOn ? "on" : "standby")
      }

      Text {
        Layout.fillWidth: true
        text: root.subtitle
        color: root.foreground
        opacity: 0.7
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
        textFormat: Text.PlainText
        elide: Text.ElideRight
      }

      RowLayout {
        Layout.fillWidth: true
        spacing: Style.space(6)
        Button {
          Layout.fillWidth: true
          text: root.tvOn ? "Power off" : "Power on"
          foreground: root.foreground
          onClicked: root.power()
        }
        Button { text: "Mute"; foreground: root.foreground; onClicked: root.volume("mute") }
        Button { text: "Vol \u2212"; foreground: root.foreground; onClicked: root.volume("down") }
        Button { text: "Vol +"; foreground: root.foreground; onClicked: root.volume("up") }
      }

      ColumnLayout {
        Layout.alignment: Qt.AlignHCenter
        spacing: Style.space(4)
        Button { Layout.alignment: Qt.AlignHCenter; text: "\u25B2"; foreground: root.foreground; implicitWidth: Style.space(72); onClicked: root.key("KEY_UP") }
        RowLayout {
          spacing: Style.space(4)
          Button { text: "\u25C0"; foreground: root.foreground; implicitWidth: Style.space(72); onClicked: root.key("KEY_LEFT") }
          Button { text: "OK"; foreground: root.foreground; implicitWidth: Style.space(72); onClicked: root.key("KEY_OK") }
          Button { text: "\u25B6"; foreground: root.foreground; implicitWidth: Style.space(72); onClicked: root.key("KEY_RIGHT") }
        }
        Button { Layout.alignment: Qt.AlignHCenter; text: "\u25BC"; foreground: root.foreground; implicitWidth: Style.space(72); onClicked: root.key("KEY_DOWN") }
      }

      RowLayout {
        Layout.fillWidth: true
        spacing: Style.space(6)
        Button { Layout.fillWidth: true; text: "Back"; foreground: root.foreground; onClicked: root.key("KEY_RETURNS") }
        Button { Layout.fillWidth: true; text: "Home"; foreground: root.foreground; onClicked: root.key("KEY_HOME") }
        Button { Layout.fillWidth: true; text: "Menu"; foreground: root.foreground; onClicked: root.key("KEY_MENU") }
      }

      PanelSectionHeader { Layout.fillWidth: true; text: "Inputs" }
      Flow {
        Layout.fillWidth: true
        spacing: Style.space(6)
        Repeater {
          model: root.sources
          delegate: Button {
            required property var modelData
            text: String(modelData.label || modelData.id || "")
            foreground: root.foreground
            active: root.tv.source === modelData.id
            onClicked: root.setSource(String(modelData.id))
          }
        }
      }

      PanelSectionHeader { Layout.fillWidth: true; text: "Apps" }
      Flow {
        Layout.fillWidth: true
        spacing: Style.space(6)
        Repeater {
          model: root.apps
          delegate: Button {
            required property var modelData
            text: String(modelData.name || "")
            foreground: root.foreground
            onClicked: root.launch(String(modelData.appId))
          }
        }
      }

      Text {
        Layout.fillWidth: true
        visible: !root.paired
        text: root.errorCode === "pairing_required"
          ? "Pair first: scripts/vidaa.py pair --cert <cert.pem> --key <key.pem>"
          : "Backend error: " + root.errorCode
        color: bar ? bar.urgent : Color.urgent
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
        wrapMode: Text.Wrap
        textFormat: Text.PlainText
      }
    }
  }
}
