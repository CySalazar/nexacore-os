# Bundled apps

The image ships a small set of first-party apps. They are written against the
same privacy-by-construction rules as the rest of the system — anything that
could touch the network or an AI model passes through a capability gate and the
tokenization layer first.

> **A note on "library-gated" features.** Some apps have a fully working core
> (navigation, layout, selection, scheduling) but defer the heavy media-decoding
> step to a vetted decoder. Where a specific codec or driver is not present in
> the image, the app tells you rather than failing silently.

## Terminal shell

A text shell (`nexacore-shell`) for running commands and inspecting the system.
It is the most complete app today and a good place to explore. Use it to launch
other tools, read system state, and drive the OS scriptably.

## System monitor

A live view of system health: per-core **CPU** load, **memory** use, **disk**
and **network** throughput, and a **process table**. The monitor reads the
kernel's `/proc`-class metrics surface. Where you have the capability, you can
act on a process from the table (e.g. terminate or re-nice it) — these actions
are capability-gated, so they only succeed if your session is allowed to perform
them.

## Document / PDF viewer

Open and read PDFs:

- **Continuous scroll** through a multi-page document, with a **thumbnail** rail
  for quick navigation.
- **Zoom** with explicit zoom levels plus **fit-to-width** and **fit-to-page**.
- **Select text** by dragging; double-click extends the selection to whole
  words. **Copy** the selection to the clipboard.
- **Print** the document (or a page range) to a configured printer via the print
  subsystem.

The rendering of page pixels and text extraction use a vetted PDF engine; the
viewer's navigation, selection, zoom, and print orchestration are part of the
system.

## Image viewer

View and lightly edit images (PNG / JPEG / WebP / AVIF):

- **Zoom and pan** with a fit-to-screen option.
- **Crop**, **rotate** (90°/180°/270°), and **flip**.
- **Annotate** — highlights, arrows, and text blocks composited over the image.

The pixel decode for each format is provided by a vetted codec; the buffer
manipulation, viewport, and annotation layers are part of the system.

## Media player

Play audio and video (MP4 / MKV-WebM containers; H.264 / VP9 video, Opus / AAC
audio):

- **Playlist** with shuffle.
- Audio-mastered **A/V sync** so sound and picture stay aligned.
- Hardware-accelerated decode where available, with a software fallback.

As with the other viewers, the actual codec is a vetted, gated component; the
demux, sync, scheduling, and playlist logic are part of the system.

## The NexaCore Helper

An always-available system agent that can act on your behalf — but only under
explicit, auditable rules:

- It proposes an action and shows you its **impact** across four axes: privacy,
  trust, cost, and time.
- Higher-impact actions require your **authorization** before they run.
- Every action passes a **capability gate** and charges your **privacy budget**;
  a pre-action snapshot enables a short **undo** window, and everything is
  **audited**.

This means the assistant cannot quietly send your data somewhere or run a costly
operation without surfacing it first.

## Privacy you can see

Across all of these apps, two guarantees hold:

- **Tokenization before egress.** Personally identifiable information is replaced
  with tokens before any text can reach an AI model or leave the device.
- **A privacy budget.** Operations that disclose information draw down a budget
  you can inspect, so "where did my data go?" has a concrete answer.
