import { PageHeader } from "../components/ui";

export default function About() {
  return (
    <div>
      <PageHeader title="About" sub="What this tool is, what it is not, and how it stays safe." />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <section className="card space-y-3 p-5">
          <h2 className="font-semibold">What it does</h2>
          <p className="text-dim">Automated MCP Pentester analyzes Model Context Protocol servers and configurations for evidence-backed security issues: hidden or deceptive Unicode, prompt and tool poisoning, weak input schemas, dangerous capability combinations, tool-name collisions, and (optionally) dynamically confirmed input-validation gaps.</p>
          <h2 className="pt-2 font-semibold">What it does not do</h2>
          <ul className="list-disc space-y-1 pl-5 text-dim"><li>It never executes uploaded files or tool metadata.</li><li>It never runs shell commands from scanned content.</li><li>It never fetches arbitrary URLs: egress is SSRF-guarded and pinned to the validated address.</li><li>Dynamic probes are inert: echo markers and read-only sentinels only.</li><li>It cannot prove the absence of vulnerabilities.</li></ul>
        </section>
        <section className="card space-y-3 p-5">
          <h2 className="font-semibold">Evidence principles</h2>
          <ul className="list-disc space-y-1 pl-5 text-dim"><li><b className="text-fg">Evidence over appearance.</b> Every finding carries evidence and a reason.</li><li><b className="text-fg">Honest statuses.</b> confirmed, suspected, informational, not tested, not applicable, error.</li><li><b className="text-fg">Skipped is not passed.</b> Tests that did not run are shown as coverage gaps.</li><li><b className="text-fg">No fake data.</b> Every number in this interface comes from the backend. Local test targets are labelled DEMO DATA.</li><li><b className="text-fg">ML never overrides rules.</b> The optional model is advisory and currently unvalidated on real data.</li></ul>
          <h2 className="pt-2 font-semibold">Limitations</h2>
          <p className="text-dim">Static rules are heuristics over metadata, so false positives and false negatives happen. Capability inference is based on names and descriptions. The risk score is a prioritization aid, not a probability. See LIMITATIONS.md for the full list.</p>
        </section>
      </div>
    </div>
  );
}
