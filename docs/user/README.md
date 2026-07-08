# NexaCore OS — End-user guide (mdBook source)

This directory holds the **end-user documentation** for NexaCore OS (WS14-04):
installation, the desktop manual, the bundled apps, and troubleshooting. It is
written for people **installing and using** the OS — the engineering docs live
in [`/docs`](../).

It is an [mdBook](https://rust-lang.github.io/mdBook/): Markdown sources in
[`src/`](./src/), rendered to static HTML.

## Build it locally

```bash
cargo install mdbook          # one-time
mdbook build docs/user        # → docs/user/book/ (gitignored)
mdbook serve docs/user        # live preview at http://localhost:3000
```

## Structure

| File | Sub-task | Content |
|------|----------|---------|
| [`src/introduction.md`](./src/introduction.md) | — | What NexaCore OS is, what works today |
| [`src/installation.md`](./src/installation.md) | WS14-04.1 | ISO → first boot (VM / USB / Proxmox) |
| [`src/desktop.md`](./src/desktop.md) | WS14-04.2 | Desktop, windows, shortcuts, a11y |
| [`src/apps.md`](./src/apps.md) | WS14-04.3 | Bundled system apps |
| [`src/troubleshooting.md`](./src/troubleshooting.md) | WS14-04.4 | Common problems + fixes |

## Deployment

The book is built with [mdBook](https://rust-lang.github.io/mdBook/) from the
sources in this directory (`mdbook build docs/user`); the rendered output is
published to GitHub Pages.

## Still to do (device-side)

- **Screenshots** (WS14-04.8) — captured from a real boot once the desktop is
  deployed; the text already includes ASCII/box diagrams.
- **Usability test** (WS14-04.9 / .10) — a new user installs and uses the system
  following only this guide, and the gaps found are folded back in.
