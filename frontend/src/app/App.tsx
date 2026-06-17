import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ClipboardList,
  Database,
  FileSearch,
  Loader2,
  Network,
  Play,
  Search,
  ShieldAlert,
  TerminalSquare,
} from "lucide-react";
import {
  AlertCatalogItem,
  HuntPackage,
  analyzeThreatReport,
  getSampleReport,
  getSampleReports,
} from "../lib/api";

type Status = "idle" | "loading" | "ready" | "error";

const severityRank: Record<string, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
  "Medium/High": 3,
};

function unique(values: string[]) {
  return Array.from(new Set(values)).filter(Boolean);
}

function severityClass(severity: string) {
  if (severity === "Critical") return "severity critical";
  if (severity === "High") return "severity high";
  if (severity === "Medium") return "severity medium";
  return "severity mixed";
}

function Section({
  title,
  icon,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="result-section">
      <div className="section-title">
        {icon}
        <h2>{title}</h2>
      </div>
      {children}
    </section>
  );
}

function EmptyResult() {
  return (
    <div className="empty-state">
      <ShieldAlert size={36} />
      <h2>No hunt package yet</h2>
      <p>Select a sample alert or paste a report, then run analysis.</p>
    </div>
  );
}

function ListBlock({ items }: { items: string[] }) {
  if (!items.length) return <p className="muted">No items detected.</p>;
  return (
    <ul className="clean-list">
      {items.map((item) => (
        <li key={item}>{item}</li>
      ))}
    </ul>
  );
}

function IocBlock({ huntPackage }: { huntPackage: HuntPackage }) {
  const groups = [
    ["Domains", huntPackage.ioc.domains],
    ["IPs", huntPackage.ioc.ips],
    ["Hashes", huntPackage.ioc.hashes],
    ["Files", huntPackage.ioc.files],
    ["Processes", huntPackage.ioc.processes],
    ["Registry", huntPackage.ioc.registry_keys],
  ] as const;

  return (
    <div className="ioc-grid">
      {groups.map(([label, values]) => (
        <div className="ioc-group" key={label}>
          <span>{label}</span>
          <div>
            {values.length ? (
              values.map((value) => <code key={value}>{value}</code>)
            ) : (
              <em>none</em>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

function HuntPackageView({ huntPackage }: { huntPackage: HuntPackage }) {
  return (
    <div className="result-stack">
      <div className="result-header">
        <div>
          <p className="eyebrow">Hunt package</p>
          <h1>{huntPackage.report_title}</h1>
        </div>
        <code>{huntPackage.package_id}</code>
      </div>

      <Section title="Summary" icon={<FileSearch size={18} />}>
        <p className="summary-text">{huntPackage.threat_summary}</p>
      </Section>

      <Section title="Key Behaviors" icon={<AlertTriangle size={18} />}>
        <ListBlock items={huntPackage.key_behaviors} />
      </Section>

      <Section title="Indicators" icon={<Search size={18} />}>
        <IocBlock huntPackage={huntPackage} />
      </Section>

      <Section title="MITRE Mapping" icon={<Network size={18} />}>
        <div className="pill-row">
          {huntPackage.mitre_mapping.map((item) => (
            <span className="pill" key={item}>{item}</span>
          ))}
        </div>
      </Section>

      <Section title="Telemetry" icon={<Database size={18} />}>
        <div className="pill-row">
          {huntPackage.required_telemetry.map((item) => (
            <span className="pill strong" key={item}>{item}</span>
          ))}
        </div>
      </Section>

      <Section title="Checklist" icon={<ClipboardList size={18} />}>
        <ol className="ordered-list">
          {huntPackage.hunt_checklist.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ol>
      </Section>

      <Section title="Query Drafts" icon={<TerminalSquare size={18} />}>
        {huntPackage.query_drafts.length ? (
          <div className="query-stack">
            {huntPackage.query_drafts.map((query) => (
              <article className="query-box" key={`${query.platform}-${query.name}`}>
                <div>
                  <strong>{query.name}</strong>
                  <span>{query.platform}</span>
                </div>
                <pre>{query.query}</pre>
              </article>
            ))}
          </div>
        ) : (
          <p className="muted">No query draft selected for this report.</p>
        )}
      </Section>

      <Section title="Escalation" icon={<ShieldAlert size={18} />}>
        <p className="summary-text">{huntPackage.escalation_condition}</p>
        <p className="muted spaced">{huntPackage.correlation_logic}</p>
      </Section>
    </div>
  );
}

export function App() {
  const [reports, setReports] = useState<AlertCatalogItem[]>([]);
  const [selectedSlug, setSelectedSlug] = useState("");
  const [search, setSearch] = useState("");
  const [title, setTitle] = useState("Custom threat report");
  const [content, setContent] = useState("");
  const [huntPackage, setHuntPackage] = useState<HuntPackage | null>(null);
  const [status, setStatus] = useState<Status>("idle");
  const [message, setMessage] = useState("");

  useEffect(() => {
    getSampleReports()
      .then((data) => {
        const sorted = [...data].sort((a, b) => {
          const rank = (severityRank[b.severity] ?? 0) - (severityRank[a.severity] ?? 0);
          return rank || a.alert_name.localeCompare(b.alert_name);
        });
        setReports(sorted);
      })
      .catch((error: Error) => {
        setStatus("error");
        setMessage(error.message);
      });
  }, []);

  const categories = useMemo(() => unique(reports.map((report) => report.category)), [reports]);
  const sources = useMemo(() => unique(reports.map((report) => report.alert_source)), [reports]);

  const filteredReports = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return reports;
    return reports.filter((report) => {
      return [report.alert_name, report.alert_source, report.category, report.severity]
        .join(" ")
        .toLowerCase()
        .includes(query);
    });
  }, [reports, search]);

  async function loadSample(slug: string) {
    setSelectedSlug(slug);
    if (!slug) return;
    setStatus("loading");
    setMessage("Loading sample report...");
    try {
      const sample = await getSampleReport(slug);
      setTitle(sample.alert_name);
      setContent(sample.content);
      setStatus("idle");
      setMessage("");
    } catch (error) {
      setStatus("error");
      setMessage(error instanceof Error ? error.message : "Cannot load sample report");
    }
  }

  async function analyze() {
    if (!content.trim()) {
      setStatus("error");
      setMessage("Report content is required.");
      return;
    }

    setStatus("loading");
    setMessage("Analyzing report...");
    try {
      const result = await analyzeThreatReport(title.trim() || "Untitled report", content);
      setHuntPackage(result);
      setStatus("ready");
      setMessage("Hunt package generated.");
    } catch (error) {
      setStatus("error");
      setMessage(error instanceof Error ? error.message : "Analyze request failed");
    }
  }

  const selectedReport = reports.find((report) => report.slug === selectedSlug);

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand-row">
          <div className="brand-mark"><ShieldAlert size={22} /></div>
          <div>
            <h1>AI Hunt Assistant</h1>
            <p>SOC MVP</p>
          </div>
        </div>

        <div className="metric-grid">
          <div>
            <strong>{reports.length}</strong>
            <span>alert cases</span>
          </div>
          <div>
            <strong>{categories.length}</strong>
            <span>categories</span>
          </div>
          <div>
            <strong>{sources.length}</strong>
            <span>sources</span>
          </div>
        </div>

        <label className="field-label" htmlFor="sample-search">Search cases</label>
        <div className="search-box">
          <Search size={16} />
          <input
            id="sample-search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="EDR, phishing, DNS, cloud..."
          />
        </div>

        <div className="case-list" aria-label="Sample alert cases">
          {filteredReports.map((report) => (
            <button
              className={report.slug === selectedSlug ? "case-item selected" : "case-item"}
              key={report.slug}
              onClick={() => void loadSample(report.slug)}
              type="button"
            >
              <span
                className="case-name"
                style={{
                  fontSize:
                    report.alert_name.length > 35
                      ? "11px"
                      : report.alert_name.length > 25
                      ? "12px"
                      : "14px",
                }}
              >
                {report.alert_name}
              </span>
              <span className="case-meta">
                <span className={severityClass(report.severity)}>{report.severity}</span>
                <span>{report.alert_source}</span>
              </span>
            </button>
          ))}
        </div>
      </aside>

      <section className="workspace">
        <div className="input-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Threat report input</p>
              <h2>{selectedReport ? selectedReport.alert_name : "Custom report"}</h2>
            </div>
            <button className="primary-button" onClick={() => void analyze()} disabled={status === "loading"} type="button">
              {status === "loading" ? <Loader2 className="spin" size={18} /> : <Play size={18} />}
              Analyze
            </button>
          </div>

          <div className="title-row">
            <label className="field-label" htmlFor="report-title">Title</label>
            <input
              id="report-title"
              value={title}
              onChange={(event) => setTitle(event.target.value)}
              placeholder="Alert or report title"
            />
          </div>

          <textarea
            value={content}
            onChange={(event) => setContent(event.target.value)}
            placeholder="Paste threat report, alert context, or advisory text here."
          />

          {message && (
            <div className={status === "error" ? "status-line error" : "status-line"}>
              {status === "ready" ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
              {message}
            </div>
          )}
        </div>

        <div className="output-panel">
          {huntPackage ? <HuntPackageView huntPackage={huntPackage} /> : <EmptyResult />}
        </div>
      </section>
    </main>
  );
}
