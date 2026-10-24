import { QueryClientProvider } from "@tanstack/react-query";
import React, { lazy } from "react";
import ReactDOM from "react-dom/client";
import { HashRouter, Route, Routes } from "react-router-dom";
import App from "./App";
const About = lazy(() => import("./pages/About"));
const ActiveScans = lazy(() => import("./pages/ActiveScans"));
const AttackPaths = lazy(() => import("./pages/AttackPaths"));
const CommandCenter = lazy(() => import("./pages/CommandCenter"));
const UnicodeInspector = lazy(() => import("./pages/UnicodeInspector"));
const Compare = lazy(() => import("./pages/Compare"));
const Evidence = lazy(() => import("./pages/Evidence"));
const Findings = lazy(() => import("./pages/Findings"));
const Journey = lazy(() => import("./pages/Journey"));
const Insights = lazy(() => import("./pages/Insights"));
const MlAnalysis = lazy(() => import("./pages/MlAnalysis"));
const NewScan = lazy(() => import("./pages/NewScan"));
const Home = lazy(() => import("./pages/Home"));
const ScanPage = lazy(() => import("./pages/ScanPage"));
const Reports = lazy(() => import("./pages/Reports"));
const RiskAnalysis = lazy(() => import("./pages/RiskAnalysis"));
const ScanHistory = lazy(() => import("./pages/ScanHistory"));
const ScanLive = lazy(() => import("./pages/ScanLive"));
const Settings = lazy(() => import("./pages/Settings"));
const SystemHealth = lazy(() => import("./pages/SystemHealth"));
const Tools = lazy(() => import("./pages/Tools"));
import { PrefsProvider } from "./state/prefs";
import { queryClient } from "./state/queries";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <PrefsProvider>
        <HashRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
          <Routes>
            <Route path="/" element={<App />}>
              <Route index element={<Home />} />
              <Route path="scan" element={<NewScan />} />
              <Route path="active" element={<ActiveScans />} />
              <Route path="history" element={<ScanHistory />} />
              <Route path="scans/:id" element={<ScanPage />} />
              <Route path="live/:id" element={<ScanLive />} />
              <Route path="findings" element={<Findings />} />
              <Route path="tools" element={<Tools />} />
              <Route path="journey" element={<Journey />} />
              <Route path="command" element={<CommandCenter />} />
              <Route path="unicode" element={<UnicodeInspector />} />
              <Route path="attack-paths" element={<AttackPaths />} />
              <Route path="risk" element={<RiskAnalysis />} />
              <Route path="insights" element={<Insights />} />
              <Route path="ml" element={<MlAnalysis />} />
              <Route path="evidence" element={<Evidence />} />
              <Route path="reports" element={<Reports />} />
              <Route path="compare" element={<Compare />} />
              <Route path="settings" element={<Settings />} />
              <Route path="health" element={<SystemHealth />} />
              <Route path="about" element={<About />} />
            </Route>
          </Routes>
        </HashRouter>
      </PrefsProvider>
    </QueryClientProvider>
  </React.StrictMode>
);
