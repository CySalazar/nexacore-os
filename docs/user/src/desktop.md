# The desktop

After boot you land on the **NexaCore desktop** — a GPU-composited graphical
environment driven entirely by the system's own compositor, window manager, and
USB-HID input stack. This page covers the day-to-day mechanics.

## Input: keyboard and pointer

The desktop is driven by **USB keyboard and mouse** (USB-HID). On a virtual
machine, attach a USB tablet/mouse and keyboard to the VM (most hypervisors do
this by default). The pointer moves the on-screen cursor; the keyboard drives
text entry and shortcuts.

## Windows

Each app runs in a window. The window manager supports the usual operations:

- **Move** — drag the title bar.
- **Focus** — click a window to bring it to the front; the focused window
  receives keyboard input.
- **Close / minimise / maximise** — the title-bar controls.
- **Cycle windows** — the focus traversal shortcut (see below) moves keyboard
  focus between windows and, within a window, between controls.

## Keyboard shortcuts

NexaCore ships a configurable shortcut registry with **chord** support (e.g.
press a leader combination, then a key) and **conflict detection** (two actions
cannot bind the same chord). It ships with **platform presets** so the bindings
feel familiar:

| Preset | Primary modifier | Example: copy |
|--------|------------------|---------------|
| macOS-style | <kbd>⌘ Cmd</kbd> | <kbd>⌘</kbd> + <kbd>C</kbd> |
| Windows-style | <kbd>Ctrl</kbd> | <kbd>Ctrl</kbd> + <kbd>C</kbd> |

Pick the preset that matches your muscle memory. Custom bindings persist across
the session (within the live image's lifetime). If you assign a chord that is
already taken, the system rejects it and tells you which action owns it — fix
the conflict and try again.

## Notifications

Apps and the system post **notifications**. They surface as a transient **toast**
in the corner, and are collected in a **notification tray** with history, so you
can review what you missed. Opening the tray shows the backlog; dismissing a
toast does not lose it from history.

## Accessibility

Accessibility is built in, not bolted on:

- **Keyboard navigation** — <kbd>Tab</kbd> / <kbd>Shift</kbd>+<kbd>Tab</kbd>
  move focus through every control in reading order; the focused control is
  always visible.
- **Screen reader** — an accessibility tree exposes each control's role and
  label to a text-to-speech engine, so the focused element can be announced.
- **High-contrast theme** — a high-contrast palette with a guaranteed minimum
  contrast ratio for users with low vision.
- **Text scaling** — interface text can be scaled up without breaking layout.

## Visual design

The desktop uses the **NexaCore design language**: a color-managed pipeline
(sRGB / Display P3 / ICC), HiDPI/Retina-aware scaling (integer *and* fractional),
and a coherent system of icons, cursor themes, and surface materials. On a HiDPI
display the interface scales crisply rather than blurring.

## Shutting down

Because the image is **live**, shutting down (or powering off the VM) discards
all state. There is nothing to "save to disk" yet — close your windows and power
off when you are done.
