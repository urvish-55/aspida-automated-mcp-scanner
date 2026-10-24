import { Brain } from "lucide-react";
import { ContextLoader, EmptyState, ErrorState, PageHeader, Pill, Stat } from "../components/ui";
import { fmtDateTime } from "../lib/utils";
import { useMlInfo, useScans } from "../state/queries";

const pct = (v: number | undefined | null) => (v == null ? "-" : v.toFixed(3));

export default function MlAnalysis() {
  const ml = useMlInfo();
  const scans = useScans(200);
  if (ml.isLoading) return <ContextLoader message="Reading model metadata…" />;
  if (ml.error) return <ErrorState title="ML status could not be loaded" message={(ml.error as Error).message} onRetry={() => void ml.refetch()} />;
  const m = ml.data;
  if (!m || !m.available) {
    return <div><PageHeader title="ML analysis" /><EmptyState icon={<Brain className="h-6 w-6" />} title="ML analysis unavailable" body={<>{m?.reason ?? "No trained model was found."} The scanner works without it: findings and the risk score never depend on the model.</>} /></div>;
  }
  const states = (scans.data?.items ?? []).reduce<Record<string, number>>((a, s) => { a[s.ml_status] = (a[s.ml_status] ?? 0) + 1; return a; }, {});
  const cm = m.confusion_matrix_test;
  const cv = m.cross_validation;
  const ind = m.independent_evaluation;
  const notReady = /not production|experimental/i.test(m.model_status ?? "");
  return (
    <div>
      <PageHeader title="ML analysis" sub="Every number on this page is read from the trained model's own metadata file." />
      <div className={`mb-4 rounded-xl border p-4 ${notReady ? "border-warn/50 bg-warn/5" : "border-line bg-panel"}`} role="note">
        <div className="flex flex-wrap items-center gap-2"><Pill tone={notReady ? "warn" : "ok"}>{m.model_status}</Pill><span className="text-[12.5px] text-dim">{m.usage}</span></div>
        {m.dataset?.synthetic && <p className="mt-2 text-[13px]">This model was trained and tested only on <b>synthetic</b> samples ({m.dataset.total} generated rows). It has not been validated on real MCP tools, so its scores say nothing about real-world accuracy. A perfect score on synthetic data is a warning sign, not a result.</p>}
      </div>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Model" value={<span className="text-lg">{m.model_version}</span>} hint={m.model_type} />
        <Stat label="Real-world training samples" value={m.real_world_training_samples ?? "unknown"} hint={m.dataset?.synthetic ? "none: synthetic only" : undefined} />
        <Stat label="Synthetic share" value={m.synthetic_share == null ? "unknown" : `${Math.round(m.synthetic_share * 100)}%`} />
        <Stat label="Input" value={<span className="text-base">{m.input ? "description text" : `${m.feature_count} features`}</span>} hint={`trained ${fmtDateTime(m.trained_at)}`} />
      </div>
      {cv ? (
        <>
          <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
            <section className="card p-4"><h2 className="mb-3 font-semibold">Cross-validation (grouped by server)</h2>
              <dl className="grid grid-cols-2 gap-3">{[["Recall @ 1% false positives", cv.recall_at_fpr_1pct], ["Recall @ 0.1% false positives", cv.recall_at_fpr_0_1pct], ["ROC-AUC", cv.roc_auc], ["PR-AUC", cv.pr_auc]].map(([k, v]) => <div key={String(k)} className="rounded-lg bg-raised p-3"><dt className="label">{k}</dt><dd className="mt-1 text-xl font-semibold tabular-nums">{pct(v as number)}</dd></div>)}</dl>
              <p className="mt-3 text-[12.5px] text-dim">Length-only baseline recall at 1% false positives: {pct(cv.length_only_baseline_recall_at_fpr_1pct)} (shows the model is not just reading description length). Dataset: {m.dataset?.positive} attack and {m.dataset?.negative} benign-candidate descriptions.</p>
              {m.leave_one_template_out_recall && <p className="mt-1 text-[12.5px] text-dim">Leave-one-attack-template-out recall: {Object.entries(m.leave_one_template_out_recall).map(([k, v]) => `${k} ${pct(v)}`).join(" · ")}</p>}
            </section>
            <section className="card p-4"><h2 className="mb-3 font-semibold">Independent check <Pill tone="warn">small sample</Pill></h2>
              {ind ? <>
                <p className="text-[13px]">Hand-written attacks the model had not seen: caught <b>{ind.hits} of {ind.positives}</b>. Real benign tools from other repositories wrongly flagged: <b>{ind.false_positives} of {ind.negatives}</b>.</p>
                {ind.missed.length > 0 && <><p className="label mt-3">Missed</p><ul className="mt-1 space-y-1 text-[12.5px]">{ind.missed.map((x) => <li key={x.name + x.source} className="flex justify-between gap-2"><span className="mono">{x.name}</span><span className="text-dim">{x.source} · score {x.score}</span></li>)}</ul></>}
                <p className="mt-3 text-[12.5px] text-dim">{ind.note}</p>
              </> : <p className="text-dim">Not recorded.</p>}
            </section>
          </div>
          {(m.caveats ?? []).length > 0 && <section className="card mt-4 p-4"><h2 className="mb-2 font-semibold">Read this before trusting the numbers</h2><ul className="list-disc space-y-1 pl-5 text-[13px] text-dim">{(m.caveats ?? []).map((c) => <li key={c}>{c}</li>)}</ul>{m.dataset?.label_quality && <p className="mt-2 text-[12.5px] text-dim">{m.dataset.label_quality}</p>}</section>}
        </>
      ) : (
      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <section className="card p-4"><h2 className="mb-3 font-semibold">Test-set metrics {m.dataset?.synthetic && <Pill tone="warn">synthetic</Pill>}</h2>
          {m.test ? <dl className="grid grid-cols-2 gap-3">{[["Precision", m.test.precision], ["Recall", m.test.recall], ["F1", m.test.f1], ["Balanced accuracy", m.test.balanced_accuracy]].map(([k, v]) => <div key={String(k)} className="rounded-lg bg-raised p-3"><dt className="label">{k}</dt><dd className="mt-1 text-xl font-semibold tabular-nums">{pct(v as number)}</dd></div>)}</dl> : <p className="text-dim">No test metrics were recorded.</p>}
          {m.cv_f1_train && <p className="mt-3 text-[12.5px] text-dim">Cross-validated F1 (train): {pct(m.cv_f1_train.mean)} ± {pct(m.cv_f1_train.std)}</p>}
          <p className="mt-1 text-[12.5px] text-dim">Dataset: {m.dataset?.total} rows ({m.dataset?.positive} positive, {m.dataset?.negative} negative), test {m.dataset?.test_size}, seed {m.dataset?.seed}.</p>
        </section>
        <section className="card p-4"><h2 className="mb-3 font-semibold">Confusion matrix (test)</h2>
          {cm ? <table className="mx-auto text-center"><thead><tr><th /><th className="label px-4 pb-2">Pred. {cm.labels[0]}</th><th className="label px-4 pb-2">Pred. {cm.labels[1]}</th></tr></thead><tbody>{cm.matrix.map((r, i) => <tr key={i}><th className="label pr-3 text-right">{cm.labels[i]}</th>{r.map((v, j) => <td key={j} className={`h-16 w-28 rounded-lg border border-line text-xl font-semibold tabular-nums ${i === j ? "bg-ok/15 text-ok" : "bg-sev-critical/10 text-sev-critical"}`}>{v}</td>)}</tr>)}</tbody></table> : <p className="text-dim">Not recorded.</p>}
        </section>
      </div>
      )}
      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <section className="card p-4"><h2 className="mb-2 font-semibold">Per-scan ML status</h2>{Object.keys(states).length === 0 ? <p className="text-dim">No scans yet.</p> : <ul className="space-y-1">{Object.entries(states).map(([k, v]) => <li key={k} className="flex justify-between"><span>{k}</span><span className="tabular-nums text-dim">{v} scan(s)</span></li>)}</ul>}</section>
        <section className="card p-4"><h2 className="mb-2 font-semibold">{m.thresholds ? "Operating thresholds" : `Features (${m.feature_count})`}</h2>{m.thresholds && <p className="mb-2 text-[13px]">Review ≥ <b>{m.thresholds.review}</b> · High ≥ <b>{m.thresholds.high}</b>. <span className="text-dim">{m.thresholds.meaning}</span></p>}<div className="flex max-h-40 flex-wrap gap-1.5 overflow-y-auto" tabIndex={0} role="region" aria-label="Model features">{(m.features ?? []).map((f) => <span key={f} className="chip mono">{f}</span>)}</div></section>
      </div>
      <p className="mt-4 text-[12.5px] text-dim">{m.note}</p>
    </div>
  );
}
