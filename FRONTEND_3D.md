# 3D investigation interface

3D is used as an investigation surface, not decoration: every object is a stored backend record and every interaction has a 2D equivalent.

## Data → scene (no invented data)

| Scene object | Source |
|---|---|
| Server (core) | scan target label |
| Tool (sphere) | stored tool definitions (`GET /api/scans/{id}`) |
| Capability (cube) | `capabilities` of each tool (static inference) |
| Finding (octahedron, size by severity) | persisted findings; edges to affected tools |
| Attack-path stages | `GET /api/scans/{id}/analysis` `attack_paths`; solid = `evidenced`, wireframe = `potential`, ring = `missing`; overall status never above "suspected" |
| Risk terrain bars | RISK-1 per-finding points per category × severity, before caps (not the scan score) |
| Scan mode | stage derived from stored backend events; only the active stage of a *running* scan pulses |
| Capability combos | highlighted only when the backend emitted a `CAP-010` finding |
| Comparison overlay | `GET /api/compare`; "no longer detected", never "resolved" |

Not shown, by design: resources and prompts (not analysed by the backend), any fabricated edge or progress, any animation for a scan that is not running.

## Architecture

`lib/securityGraph.ts` (data → graph) → `lib/sceneModel.ts` (graph → positioned items/lines per mode) → `lib/highlight.ts` (selection/hover/path emphasis)
→ renderers: `components/3d/*` (instanced meshes, line segments, drei Html labels, OrbitControls camera rig) or `components/security/Fallback2D.tsx`.
UI state (selection, filters, mode, quality) is a zustand store (`state/investigation.ts`); server state stays in TanStack Query.

## Performance

Instanced meshes (one draw call per shape), one line-segment buffer, demand-driven frame loop (renders only on change; continuous only while a running scan pulses),
paused when the tab is hidden, geometry/material disposal, label budget by quality tier, `three` in its own lazy chunk, DPR cap by tier.

## Accessibility

Canvas has a label and keyboard orbit/pan (arrow keys); an object list with the same selection state is the text equivalent; severity is text + glyph + size, never colour alone;
`prefers-reduced-motion` and Effects=Off make the camera jump instead of glide and remove pulses.

## Security

MCP names/descriptions are attacker-controlled. They are rendered only as React text nodes and pass through `safeLabel` (invisible/bidi characters become `⟦U+XXXX⟧`). No `dangerouslySetInnerHTML`, no HTML from the backend.

## Known limits

No bloom/post-processing. Live URL scans have no descriptions/capabilities until the backend stores them, and findings appear only when risk aggregation finishes. 3D is disabled below 768px (2D is used).
Remediation status is the backend's triage status; the UI changes it only through the existing triage control. Not tested on a real GPU (CI-style software rendering only).

## Scroll story: `#/journey` (v0.5.0)

A cinematic, scroll-driven walkthrough (12 sections) rendered from **your stored scan data**. Open it from the sidebar ("3D Journey") or go to `#/journey`.

**How it works.** One passive, rAF-throttled scroll listener (`hooks/useScrollProgress.ts`) writes progress into a zustand store; `lib/storyTimeline.ts` maps progress to section and camera pose; the R3F frame loop reads the store without React renders. The scene model is the same one the Command Center uses (`securityGraph` → `sceneModel` → `highlight`).

**Data honesty.**
- Every number comes from the selected scan (picker in the nav). No scan: "No scan has been performed." / "Data unavailable". Risk with no score: "Risk score unavailable."
- "Illustrative example" in the picker shows a labelled Demo Environment (no risk score, never presented as a scan).
- Attack paths are always "suspected"; only evidenced stages are solid. Resources and prompts are not analysed.
- Verification: RESOLVED only if an earlier scan of the same target had the finding, the latest does not, and it is marked resolved in tracking; otherwise STILL PRESENT or NOT VERIFIED.
- Evidence is shown as plain text via the shared CodeViewer; tool text goes through `safeLabel`; no HTML from MCP data is rendered.

**Fallbacks.** No WebGL, context loss, or screens under 768px → 2D view of the same story. `prefers-reduced-motion` → static camera, no count-up, no transitions. Same navigation and content in all modes.

**Tests.** `lib/storyTimeline.test.ts`, `lib/storyData.test.ts`, `pages/Journey.test.tsx`; browser checks were run with software WebGL (scroll through all 12 sections, nav, 2D fallback, reduced motion, 390/320px, empty/failed API, axe: 0 violations).

### v0.5.1 cinematic pass

- **MCP Security Core** (`components/story/SecurityCore.tsx`): glass shell with edge lines, metallic inner frame, nucleus, three rotating scanning rings with tick marks, procedural circuit traces with travelling pulses, base platform. Pure procedural geometry, deterministic, disposed on unmount. It is decorative and encodes no scan data.
- **Environment** (`Environment.tsx`): far wireframe structures, instanced mid-ground pylons (fewer on lower quality tiers), concentric platform rings. The old infinite grid is gone. `Streams` animate light along structural connections.
- **Scanner**: a scroll-tied scanning field makes three passes in Testing and one pass to the finding in Verify. It is an illustration; the stage list in the panel is the scan's recorded state (`deriveStages` over stored events).
- **Threat**: world slows to 25% at the threat and nearly freezes for evidence; containment ring; very subtle camera shake (full motion only). Remediation/verify never show "fixed" unless the backend marks it resolved.
- **Interaction**: click a tool/finding to fly the camera to it (cleared when you scroll to another section); path steps are clickable; "Explore in Dashboard" opens the Command Center on the object.
- **Loading** (`BootOverlay.tsx`): reflects real frontend initialisation only (chunk loaded, canvas created, first frame). Never backend progress. Absent in 2D and reduced motion; auto-dismisses after 8 s.
- **SKIP 3D EXPERIENCE** in the nav switches to the 2D version (animated SVG core, same story); remembered for the browser session.
- Not used: GSAP (the central timeline in `storyTimeline.ts` is the single scroll engine), post-processing/bloom, Resources as scene objects (the scanner does not analyse resources).
