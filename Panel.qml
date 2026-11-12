import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// Hisense VIDAA TV remote in the Omarchy bar.
// Backend: scripts/vidaa.py — one singleton MQTT daemon owned by the CLI, a
// state file this widget watches, and one-shot CLI calls per key press. No
// socket, no long-lived child and no TV protocol in this file.
Panel {
  id: root

  moduleName: "meviusisback.hisense-tv"
  ipcTarget: "meviusisback.hisense-tv"
  manageIpc: false

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color accent: Color.accent
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  // Last good state. Never replaced by a malformed, oversized or expired
  // document: a stale cache would otherwise claim the TV is live forever.
  property var tv: ({
    available: false, power: "unknown", statetype: "", volume: null, muted: false,
    source: "", channel: "", app: "", apps: [], sources: [], written: 0, stale: true
  })
  property bool stateSeen: false
  property string statePath: ""
  property string errorCode: ""     // carried by the state document
  property string actionError: ""   // carried by the last control reply
  property bool busy: false
  property int pendingVolume: 0
  property string pendingKey: ""
  property var pendingRun: null

  readonly property bool barShowsStatus: String(root.setting("barDisplay", "Status")).toLowerCase() === "status"
  readonly property bool showVolume: root.setting("showVolume", true) === true
  readonly property string displayError: root.actionError !== "" ? root.actionError : root.errorCode
  readonly property bool tvOn: root.tv && root.tv.power === "on"
  readonly property var sources: (root.tv && root.tv.sources) || []
  readonly property var apps: (root.tv && root.tv.apps) || []
  readonly property bool fresh: root.stateSeen && !root.tv.stale && root.displayError === ""

  readonly property string subtitle: {
    if (root.displayError !== "") return root.codeText(root.displayError)
    if (!root.stateSeen) return "No data yet"
    if (!root.tvOn) return "Standby"
    if (root.tv.app) return root.tv.app
    if (root.tv.channel) return root.tv.channel
    return root.tv.source || "On"
  }

  function codeText(code) {
    switch (code) {
    case "pairing_required": return "Not paired — run vidaa.py pair"
    case "tv_identity_changed": return "TV certificate changed — re-pair"
    case "cert_permissions": return "Cert/key permissions (need 0600)"
    case "cert_invalid": return "Cert/key unusable"
    case "unsafe_dir": return "Unsafe config/state directory"
    case "tv_unreachable": return "TV unreachable"
    case "backend_error": return "Backend failed to start"
    case "bad_request": return "Rejected by the backend"
    default: return code
    }
  }

  function barText() {
    if (!root.barShowsStatus) return "\u25A3"
    if (root.displayError !== "" || !root.stateSeen) return "TV"
    var text = root.tvOn ? (root.tv.app || root.tv.channel || "TV") : "TV"
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
    // The exec bit and shebang are not trusted: run the script through the
    // absolute interpreter, isolated (-I) and unbuffered (-u).
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
    // A document from a previous boot (or from a daemon that died hours ago)
    // is not live data. Leave stateSeen false so the fallback timer keeps
    // asking the CLI, which respawns the daemon.
    var stamp = typeof parsed.written === "number" ? parsed.written : parsed.updated
    var age = typeof stamp === "number" ? (Date.now() / 1000 - stamp) : Infinity
    if (age < 0 || age > 180) {
      root.stateSeen = false
      return
    }
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
      written: typeof stamp === "number" ? stamp : 0,
      stale: parsed.stale === true || parsed.available !== true
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
    root.errorCode = typeof parsed.code === "string" ? parsed.code : ""
    if (next.stale && root.errorCode === "") root.errorCode = "tv_unreachable"
    root.tv = next
    root.stateSeen = true
  }

  // One action at a time: discrete presses are dropped while busy, volume and
  // D-pad input are coalesced so a fast wheel/tap burst is not lost.
  function start(args) {
    root.busy = true
    actionProc.command = root.cliArgv(args)
    actionProc.running = true
  }

  function run(args) {
    if (root.busy) {
      // One slot is enough: the last explicit press is what the user meant.
      root.pendingRun = args
      return
    }
    root.start(args)
  }

  function queueVolume(step) {
    root.pendingVolume += step
    root.pump()
  }

  function queueKey(name) {
    root.pendingKey = name
    root.pump()
  }

  function pump() {
    if (root.busy) return
    if (root.pendingRun !== null) {
      var args = root.pendingRun
      root.pendingRun = null
      root.start(args)
      return
    }
    if (root.pendingVolume !== 0) {
      var step = root.pendingVolume
      root.pendingVolume = 0
      root.start(["vol", step > 0 ? "up" : "down"])
      return
    }
    if (root.pendingKey !== "") {
      var name = root.pendingKey
      root.pendingKey = ""
      root.start(["key", name])
    }
  }

  function key(name) { root.queueKey(name) }
  function volume(action) {
    if (action === "up") root.queueVolume(1)
    else if (action === "down") root.queueVolume(-1)
    else root.run(["vol", action])
  }
  function setSource(id) { root.run(["source", id]) }
  function launch(appId) { root.run(["app", appId]) }
  function power() { root.run(["power"]) }

  IpcHandler {
    target: "meviusisback.hisense-tv"
    function open(): void { root.open() }
    function close(): void { root.close() }
    function toggle(): void { root.toggle() }
    function refresh(): void { root.run(["status"]) }
  }

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
    onLoadFailed: {
      // The daemon unlinks the file on shutdown, so a missing document after
      // a successful load means "backend gone", not "keep showing the cache".
      if (!root.stateSeen) return
      root.stateSeen = false
      root.errorCode = root.errorCode || "tv_unreachable"
      root.tv = Object.assign({}, root.tv, { stale: true })
    }
    onLoaded: root.readState()
    // text() is stale inside the change signal, so reload() first.
    onFileChanged: reload()
  }

  // The document is only re-evaluated when it changes, so a daemon that died
  // (or a file deleted on shutdown) needs an explicit age check to stop being
  // shown as live.
  Timer {
    interval: 30000
    repeat: true
    running: true
    onTriggered: {
      if (!root.stateSeen) return
      var stamp = root.tv.written || 0
      if (stamp > 0 && Date.now() / 1000 - stamp < 120) return
      root.stateSeen = false
      root.tv = Object.assign({}, root.tv, { stale: true })
      root.run(["status"])
    }
  }

  // Only while no fresh state exists: re-ask for the path and refresh, slowly.
  // This is also what starts the daemon after a reboot.
  Timer {
    interval: 30000
    repeat: true
    running: !root.stateSeen || root.displayError !== ""
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
          if (parsed && parsed.ok === false) root.actionError = String(parsed.code || "bad_request")
          else if (parsed && parsed.ok === true) root.actionError = ""
          else root.actionError = "backend_error"
        } catch (e) {
          root.actionError = "backend_error"
        }
      }
    }
    onExited: function(exitCode) {
      root.busy = false
      if (exitCode !== 0 && root.actionError === "") root.actionError = "backend_error"
      root.pump()
      stateView.reload()
    }
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
    active: root.tvOn && root.fresh
    useActiveColor: true
    activeColor: root.accent
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.RightButton) root.run(["status"])
      else root.toggle()
    }
    onWheelMoved: function(delta) {
      if (!root.tvOn) return
      root.queueVolume(delta > 0 ? 1 : -1)
    }
  }

  // ---------------- remote panel ----------------
  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: panel.loadedContent
    contentWidth: Style.space(360)
    contentHeight: panel.fittedContentHeight(panel.loadedContentHeight, Style.space(640))

    content: PanelKeyCatcher {
      id: keyCatcher
      implicitHeight: column.implicitHeight
      onCloseRequested: root.close()
      onMoveRequested: function(dx, dy) {
        if (dy !== 0) root.queueKey(dy < 0 ? "KEY_UP" : "KEY_DOWN")
        else if (dx !== 0) root.queueKey(dx < 0 ? "KEY_LEFT" : "KEY_RIGHT")
      }
      onActivateRequested: root.queueKey("KEY_OK")

      ColumnLayout {
        id: column
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        spacing: Style.space(8)

        PanelSectionHeader {
          Layout.fillWidth: true
          text: "Hisense " + (root.tvOn && root.fresh ? "on" : "standby")
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
          Button { text: "Mute"; foreground: root.foreground; onClicked: root.run(["vol", "mute"]) }
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
          visible: root.displayError !== ""
          text: root.displayError === "pairing_required"
            ? "Pair first: scripts/vidaa.py pair --cert <cert.pem> --key <key.pem>"
            : root.codeText(root.displayError)
          color: bar ? bar.urgent : Color.urgent
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.Wrap
          textFormat: Text.PlainText
        }
      }
    }
  }
}
