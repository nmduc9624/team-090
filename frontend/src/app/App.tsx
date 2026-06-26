import { useEffect, useMemo, useState } from "react";
import type { User } from "firebase/auth";
import { onAuthStateChanged, signInWithEmailAndPassword, signOut } from "firebase/auth";
import {
  AlertTriangle,
  Bell,
  CheckCircle2,
  ClipboardList,
  Database,
  FileSearch,
  Loader2,
  Network,
  Plus,
  Play,
  Search,
  ShieldAlert,
  TerminalSquare,
  X,
} from "lucide-react";
import { firebaseAuth } from "../lib/firebase";
import {
  AlertCatalogItem,
  AppNotification,
  CaseSummary,
  CaseTimelineEvent,
  HuntPackage,
  InvestigationStep,
  analyzeThreatReport,
  askSupervisor,
  getCaseDetail,
  getCases,
  getNotifications,
  getSampleReport,
  getSampleReports,
  markNotificationRead,
  sendWarningEvent,
  setAuthTokenProvider,
} from "../lib/api";

type Status = "idle" | "loading" | "ready" | "error";
type SidebarMode = "processing" | "history" | "search";

type ReportWorkspace = {
  id: string;
  name: string;
  selectedSlug: string;
  title: string;
  content: string;
  huntPackage: HuntPackage | null;
  status: Status;
  message: string;
  priorityConfirmed: boolean;
  workedStepIds: string[];
  escalationSent: boolean;
  finalSummarySent: boolean;
  timeline: CaseTimelineEvent[];
};

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

function compactList(values: string[], limit = 6) {
  return values.filter(Boolean).slice(0, limit);
}

function buildSupervisorContext(huntPackage: HuntPackage, selectedStep?: InvestigationStep, completedSteps: string[] = []) {
  const activeStep =
    selectedStep ??
    huntPackage.investigation_flow.find((step) => step.status !== "completed") ??
    huntPackage.investigation_flow[0];
  const evidenceAvailable = compactList([
    ...(activeStep?.expected_evidence ?? []),
    ...huntPackage.required_telemetry,
    ...huntPackage.key_behaviors,
    ...huntPackage.ioc.domains,
    ...huntPackage.ioc.ips,
    ...huntPackage.ioc.files,
    ...huntPackage.ioc.processes,
  ]);

  return {
    severity: huntPackage.severity_hint,
    confidence_score: huntPackage.confidence_score,
    current_step: activeStep
      ? `${activeStep.title}: ${activeStep.description}`
      : "No current investigation step is selected.",
    completed_steps: completedSteps,
    evidence_available: evidenceAvailable,
    current_warning: huntPackage.warning_preview?.message ?? "",
  };
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

function NotificationPanel({
  notifications,
  onDismiss,
  onOpenCase,
}: {
  notifications: AppNotification[];
  onDismiss: (notificationId: string) => void;
  onOpenCase: (caseId: string) => void;
}) {
  const unread = notifications.filter((notification) => !notification.read).slice(0, 5);
  return (
    <section className="notification-panel" aria-label="Supervisor replies">
      <div className="notification-heading">
        <span><Bell size={14} /> Supervisor replies</span>
        <strong>{unread.length}</strong>
      </div>
      {unread.length === 0 ? (
        <p className="notification-empty">No replies yet.</p>
      ) : (
        <div className="notification-list">
          {unread.map((notification) => (
            <article className="notification-card" key={notification.notification_id}>
              <div>
                <strong>{notification.author_name || "Discord reply"}</strong>
                <button
                  aria-label="Dismiss notification"
                  onClick={() => onDismiss(notification.notification_id)}
                  type="button"
                >
                  <X size={13} />
                </button>
              </div>
              <p>{notification.message}</p>
              <button className="notification-case-link" onClick={() => onOpenCase(notification.case_id)} type="button">
                {notification.case_title || notification.case_id}
              </button>
              {notification.message_url && (
                <a href={notification.message_url} rel="noreferrer" target="_blank">
                  Open in Discord
                </a>
              )}
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function LoginScreen({
  onLogin,
  error,
  loading,
}: {
  onLogin: (email: string, password: string) => void;
  error: string;
  loading: boolean;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  return (
    <main className="login-shell">
      <section className="login-panel">
        <div className="brand-mark large"><ShieldAlert size={30} /></div>
        <p className="eyebrow">SOC Hunt Assistant</p>
        <h1>Sign in to continue</h1>
        <p className="muted">Use the Firebase Email/Password account assigned for this SOC workflow.</p>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            onLogin(email.trim(), password);
          }}
        >
          <label htmlFor="login-email">Email</label>
          <input
            id="login-email"
            autoComplete="email"
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            placeholder="junior@example.com"
            required
          />
          <label htmlFor="login-password">Password</label>
          <input
            id="login-password"
            autoComplete="current-password"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="Password"
            required
          />
          {error && <p className="auth-error">{error}</p>}
          <button className="primary-button" type="submit" disabled={loading}>
            {loading ? <Loader2 className="spin" size={18} /> : null}
            Sign in
          </button>
        </form>
      </section>
    </main>
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

function InvestigationFlow({
  huntPackage,
  workedStepIds,
  onStartStep,
  onAskForHelp,
}: {
  huntPackage: HuntPackage;
  workedStepIds: string[];
  onStartStep: (step: InvestigationStep, index: number) => void;
  onAskForHelp: (step: InvestigationStep, index: number) => void;
}) {
  const steps = huntPackage.investigation_flow ?? [];
  if (!steps.length) return <p className="muted">No investigation flow generated.</p>;
  return (
    <div className="workflow-list">
      {steps.map((step, index) => {
        const stepKey = step.step_id || `${step.title}-${index}`;
        const alreadyStarted = workedStepIds.includes(stepKey);
        return (
          <article className="workflow-row" key={stepKey}>
            <div className="step-index">{index + 1}</div>
            <div>
              <div className="workflow-heading">
                <strong>{step.title}</strong>
                <div className="workflow-actions">
                  <button
                    className="workflow-button"
                    disabled={alreadyStarted}
                    onClick={() => onStartStep(step, index)}
                    type="button"
                  >
                    {alreadyStarted ? "Started" : "Start this step"}
                  </button>
                  <button
                    className="workflow-button secondary"
                    onClick={() => onAskForHelp(step, index)}
                    type="button"
                  >
                    Ask for help
                  </button>
                </div>
              </div>
              <p>{step.description}</p>
              {step.expected_evidence.length > 0 && (
                <div className="mini-pill-row">
                  {step.expected_evidence.map((item) => (
                    <span key={item}>{item}</span>
                  ))}
                </div>
              )}
            </div>
          </article>
        );
      })}
    </div>
  );
}

function PriorityActions({
  huntPackage,
  confirmed,
  onConfirm,
}: {
  huntPackage: HuntPackage;
  confirmed: boolean;
  onConfirm: () => void;
}) {
  const actions = huntPackage.priority_actions ?? [];
  if (!actions.length) return <p className="muted">No priority actions generated.</p>;
  return (
    <div className="workflow-group">
      <div className="section-action-row">
        <p className="muted">Confirm these first actions when the analyst is ready to send them into the Discord ticket.</p>
        <button className="workflow-button action" disabled={confirmed} onClick={onConfirm} type="button">
          {confirmed ? "Priority warning sent" : "Confirm priority actions"}
        </button>
      </div>
      <div className="workflow-list compact">
        {actions.map((action) => (
          <article className="workflow-row" key={action.action_id || action.title}>
            <div className="step-index action">!</div>
            <div>
              <div className="workflow-heading">
                <strong>{action.title}</strong>
                <span>{action.recommended_time.replace(/_/g, " ")}</span>
              </div>
              <p>{action.why_it_matters}</p>
              {action.requires_approval && <p className="approval-note">Requires supervisor approval before execution.</p>}
            </div>
          </article>
        ))}
      </div>
    </div>
  );
}

function TimelineBlock({ huntPackage }: { huntPackage: HuntPackage }) {
  const events = huntPackage.timeline_or_attack_path ?? [];
  if (!events.length) return <p className="muted">No timeline or attack path generated.</p>;
  return (
    <div className="timeline-list">
      {events.map((event) => (
        <article className="timeline-row" key={`${event.order}-${event.stage}`}>
          <span>{event.order}</span>
          <div>
            <strong>{event.stage}</strong>
            <p>{event.description}</p>
            {event.evidence_needed.length > 0 && (
              <div className="mini-pill-row">
                {event.evidence_needed.map((item) => (
                  <span key={item}>{item}</span>
                ))}
              </div>
            )}
          </div>
        </article>
      ))}
    </div>
  );
}

function CaseActivityTimeline({ events }: { events: CaseTimelineEvent[] }) {
  if (!events.length) return <p className="muted">No case activity recorded yet.</p>;
  return (
    <div className="case-activity-list">
      {events.map((event, index) => (
        <article className="case-activity-row" key={`${event.timestamp}-${event.type}-${index}`}>
          <span>{event.type.replace(/_/g, " ")}</span>
          <div>
            <strong>{event.label}</strong>
            <p>{event.detail || "No extra detail."}</p>
            <time>{event.timestamp || "unknown time"}</time>
          </div>
        </article>
      ))}
    </div>
  );
}

function WarningPreview({ huntPackage }: { huntPackage: HuntPackage }) {
  const warning = huntPackage.warning_preview;
  if (!warning?.message) return <p className="muted">No warning preview generated.</p>;
  return (
    <div className={warning.should_send ? "warning-preview active" : "warning-preview"}>
      <div>
        <strong>{warning.should_send ? "Warning recommended" : "Warning not recommended yet"}</strong>
        <span>Recipient: {warning.recipient_role}</span>
      </div>
      <pre>{warning.message}</pre>
      {warning.requires_confirmation && <p>Analyst confirmation is required before sending.</p>}
    </div>
  );
}

function HuntPackageView({
  huntPackage,
  priorityConfirmed,
  workedStepIds,
  escalationSent,
  finalSummarySent,
  onConfirmPriority,
  onStartStep,
  onAskForHelp,
  onSendEscalation,
  onEndCase,
  timeline,
}: {
  huntPackage: HuntPackage;
  priorityConfirmed: boolean;
  workedStepIds: string[];
  escalationSent: boolean;
  finalSummarySent: boolean;
  onConfirmPriority: () => void;
  onStartStep: (step: InvestigationStep, index: number) => void;
  onAskForHelp: (step: InvestigationStep, index: number) => void;
  onSendEscalation: () => void;
  onEndCase: () => void;
  timeline: CaseTimelineEvent[];
}) {
  return (
    <div className="result-stack">
      <div className="result-header">
        <div>
          <p className="eyebrow">Hunt package</p>
          <h1>{huntPackage.report_title}</h1>
        </div>
        <div className="result-actions">
          <code>{huntPackage.package_id}</code>
        </div>
      </div>

      <Section title="Summary" icon={<FileSearch size={18} />}>
        <p className="summary-text">{huntPackage.threat_summary}</p>
      </Section>

      <Section title="Risk Explanation" icon={<ShieldAlert size={18} />}>
        <p className="summary-text">{huntPackage.risk_explanation || "No risk explanation generated."}</p>
      </Section>

      <Section title="Key Behaviors" icon={<AlertTriangle size={18} />}>
        <ListBlock items={huntPackage.key_behaviors} />
      </Section>

      <Section title="Priority Actions" icon={<AlertTriangle size={18} />}>
        <PriorityActions huntPackage={huntPackage} confirmed={priorityConfirmed} onConfirm={onConfirmPriority} />
      </Section>

      <Section title="Investigation Flow" icon={<ClipboardList size={18} />}>
        <InvestigationFlow
          huntPackage={huntPackage}
          workedStepIds={workedStepIds}
          onStartStep={onStartStep}
          onAskForHelp={onAskForHelp}
        />
      </Section>

      <Section title="Timeline / Attack Path" icon={<Network size={18} />}>
        <TimelineBlock huntPackage={huntPackage} />
      </Section>

      <Section title="Case Activity" icon={<ClipboardList size={18} />}>
        <CaseActivityTimeline events={timeline} />
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

      <Section title="False Positive Checks" icon={<CheckCircle2 size={18} />}>
        <ListBlock items={huntPackage.false_positive_checks ?? []} />
      </Section>

      <Section title="Recommended Response" icon={<ShieldAlert size={18} />}>
        <ListBlock items={huntPackage.recommended_response ?? []} />
      </Section>

      <Section title="Warning Preview" icon={<AlertTriangle size={18} />}>
        <WarningPreview huntPackage={huntPackage} />
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
        <div className="section-action-row">
          <button className="workflow-button danger" disabled={escalationSent} onClick={onSendEscalation} type="button">
            {escalationSent ? "Escalation warning sent" : "Send escalation warning"}
          </button>
        </div>
      </Section>

      <div className="end-case-row">
        <button className="workflow-button danger" disabled={finalSummarySent} onClick={onEndCase} type="button">
          {finalSummarySent ? "Final summary sent" : "End case"}
        </button>
      </div>
    </div>
  );
}

function createWorkspace(index: number): ReportWorkspace {
  const id = `report-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return {
    id,
    name: `Processing report ${index}`,
    selectedSlug: "",
    title: "Custom threat report",
    content: "",
    huntPackage: null,
    status: "idle",
    message: "",
    priorityConfirmed: false,
    workedStepIds: [],
    escalationSent: false,
    finalSummarySent: false,
    timeline: [],
  };
}

export function App() {
  const [authUser, setAuthUser] = useState<User | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [authError, setAuthError] = useState("");
  const [authLoading, setAuthLoading] = useState(false);
  const [reports, setReports] = useState<AlertCatalogItem[]>([]);
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [notifications, setNotifications] = useState<AppNotification[]>([]);
  const [sidebarMode, setSidebarMode] = useState<SidebarMode>("processing");
  const [search, setSearch] = useState("");
  const [workspaces, setWorkspaces] = useState<ReportWorkspace[]>(() => [createWorkspace(1)]);
  const [activeWorkspaceId, setActiveWorkspaceId] = useState(() => workspaces[0]?.id ?? "");

  const [isSupervisorModalOpen, setIsSupervisorModalOpen] = useState(false);
  const [struggle, setStruggle] = useState("");
  const [question, setQuestion] = useState("");
  const [helpStep, setHelpStep] = useState<InvestigationStep | undefined>(undefined);
  const [isSubmittingSupervisor, setIsSubmittingSupervisor] = useState(false);
  const [supervisorError, setSupervisorError] = useState("");
  const [isSupervisorSubmitted, setIsSupervisorSubmitted] = useState(false);

  const activeWorkspace = useMemo(() => {
    return workspaces.find((workspace) => workspace.id === activeWorkspaceId) ?? workspaces[0];
  }, [activeWorkspaceId, workspaces]);

  useEffect(() => {
    setAuthTokenProvider(async () => firebaseAuth.currentUser?.getIdToken() ?? null);
    const unsubscribe = onAuthStateChanged(firebaseAuth, (user) => {
      setAuthUser(user);
      setAuthReady(true);
    });
    return () => {
      unsubscribe();
      setAuthTokenProvider(null);
    };
  }, []);

  function updateWorkspace(id: string, patch: Partial<ReportWorkspace>) {
    setWorkspaces((items) =>
      items.map((workspace) => (workspace.id === id ? { ...workspace, ...patch } : workspace))
    );
  }

  function updateActiveWorkspace(patch: Partial<ReportWorkspace>) {
    if (!activeWorkspace) return;
    updateWorkspace(activeWorkspace.id, patch);
  }

  function addWorkspace() {
    const next = createWorkspace(workspaces.length + 1);
    setWorkspaces((items) => [...items, next]);
    setActiveWorkspaceId(next.id);
    setSidebarMode("processing");
  }

  useEffect(() => {
    if (!authUser) return;
    getSampleReports()
      .then((data) => {
        const sorted = [...data].sort((a, b) => {
          const rank = (severityRank[b.severity] ?? 0) - (severityRank[a.severity] ?? 0);
          return rank || a.alert_name.localeCompare(b.alert_name);
        });
        setReports(sorted);
      })
      .catch((error: Error) => {
        updateActiveWorkspace({ status: "error", message: error.message });
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authUser]);

  async function refreshCases() {
    try {
      const response = await getCases();
      setCases(response.cases);
    } catch (error) {
      console.error("Failed to load case history:", error);
    }
  }

  useEffect(() => {
    if (!authUser) {
      setCases([]);
      return;
    }
    void refreshCases();
  }, [authUser]);

  useEffect(() => {
    if (!authUser) {
      setNotifications([]);
      return;
    }

    let cancelled = false;
    async function refreshNotifications() {
      try {
        const response = await getNotifications();
        if (!cancelled) {
          setNotifications(response.notifications);
        }
      } catch (error) {
        console.error("Failed to load notifications:", error);
      }
    }

    void refreshNotifications();
    const intervalId = window.setInterval(() => void refreshNotifications(), 7000);
    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [authUser]);

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
    if (!activeWorkspace) return;
    updateWorkspace(activeWorkspace.id, { selectedSlug: slug });
    if (!slug) return;
    updateWorkspace(activeWorkspace.id, { status: "loading", message: "Loading sample report..." });
    try {
      const sample = await getSampleReport(slug);
      updateWorkspace(activeWorkspace.id, {
        name: sample.alert_name,
        title: sample.alert_name,
        content: sample.content,
        status: "idle",
        message: "",
      });
      setSidebarMode("processing");
    } catch (error) {
      updateWorkspace(activeWorkspace.id, {
        status: "error",
        message: error instanceof Error ? error.message : "Cannot load sample report",
      });
    }
  }

  async function openCase(caseId: string) {
    updateActiveWorkspace({ status: "loading", message: "Opening case history..." });
    try {
      const detail = await getCaseDetail(caseId);
      if (!detail.hunt_package) {
        updateActiveWorkspace({ status: "error", message: "No hunt package stored for this case." });
        return;
      }
      const workspaceId = `case-${caseId}`;
      const restored: ReportWorkspace = {
        id: workspaceId,
        name: detail.case.title || detail.hunt_package.report_title,
        selectedSlug: "",
        title: detail.case.title || detail.hunt_package.report_title,
        content: String((detail.case.raw_report as { content?: string } | undefined)?.content ?? ""),
        huntPackage: detail.hunt_package,
        status: "ready",
        message: `Opened case history: ${detail.case.status || "unknown"}.`,
        priorityConfirmed: Boolean(detail.case.priority_actions_confirmed),
        workedStepIds: detail.steps
          .filter((step) => step.status === "started" || step.status === "completed")
          .map((step, index) => step.step_id || `${step.title}-${index}`),
        escalationSent: detail.case.status === "escalated",
        finalSummarySent: detail.case.status === "ended",
        timeline: detail.timeline,
      };
      setWorkspaces((items) => {
        const exists = items.some((item) => item.id === workspaceId);
        return exists ? items.map((item) => (item.id === workspaceId ? restored : item)) : [...items, restored];
      });
      setActiveWorkspaceId(workspaceId);
      setSidebarMode("processing");
    } catch (error) {
      updateActiveWorkspace({
        status: "error",
        message: error instanceof Error ? error.message : "Cannot open case history",
      });
    }
  }

  async function analyze() {
    if (!activeWorkspace) return;
    if (!activeWorkspace.content.trim()) {
      updateWorkspace(activeWorkspace.id, { status: "error", message: "Report content is required." });
      return;
    }

    updateWorkspace(activeWorkspace.id, { status: "loading", message: "Analyzing report..." });
    try {
      const result = await analyzeThreatReport(activeWorkspace.title.trim() || "Untitled report", activeWorkspace.content);
      updateWorkspace(activeWorkspace.id, {
        name: result.report_title || activeWorkspace.title || "Analyzed report",
        title: result.report_title || activeWorkspace.title,
        huntPackage: result,
        status: "ready",
        message: "Hunt package generated.",
        priorityConfirmed: false,
        workedStepIds: [],
        escalationSent: false,
        finalSummarySent: false,
        timeline: [],
      });
      void refreshCases();
    } catch (error) {
      updateWorkspace(activeWorkspace.id, {
        status: "error",
        message: error instanceof Error ? error.message : "Analyze request failed",
      });
    }
  }

  function stepKey(step: InvestigationStep, index: number) {
    return step.step_id || `${step.title}-${index}`;
  }

  function completedStepTitles(workspace: ReportWorkspace) {
    const steps = workspace.huntPackage?.investigation_flow ?? [];
    return steps
      .filter((step, index) => workspace.workedStepIds.includes(stepKey(step, index)))
      .map((step) => step.title);
  }

  async function handleConfirmPriority() {
    if (!activeWorkspace?.huntPackage) return;
    const packageData = activeWorkspace.huntPackage;
    try {
      await sendWarningEvent(
        packageData.package_id,
        packageData.report_title,
        "priority_action_warning",
        packageData.severity_hint,
        packageData.confidence_score,
        { priority_actions: packageData.priority_actions }
      );
      updateWorkspace(activeWorkspace.id, { priorityConfirmed: true, message: "Priority warning sent to Discord ticket." });
      void refreshCases();
    } catch (error) {
      updateWorkspace(activeWorkspace.id, {
        status: "error",
        message: error instanceof Error ? error.message : "Cannot send priority warning",
      });
    }
  }

  async function handleStartStep(step: InvestigationStep, index: number) {
    if (!activeWorkspace?.huntPackage) return;
    const key = stepKey(step, index);
    if (activeWorkspace.workedStepIds.includes(key)) return;
    const packageData = activeWorkspace.huntPackage;
    try {
      await sendWarningEvent(
        packageData.package_id,
        packageData.report_title,
        "step_warning",
        packageData.severity_hint,
        packageData.confidence_score,
        {
          current_step: step,
          evidence_to_check: compactList([
            ...step.expected_evidence,
            ...packageData.required_telemetry,
            ...packageData.key_behaviors,
          ], 8),
        }
      );
      updateWorkspace(activeWorkspace.id, {
        workedStepIds: [...activeWorkspace.workedStepIds, key],
        message: `Step warning sent: ${step.title}`,
      });
      void refreshCases();
    } catch (error) {
      updateWorkspace(activeWorkspace.id, {
        status: "error",
        message: error instanceof Error ? error.message : "Cannot send step warning",
      });
    }
  }

  function handleAskForHelpStep(step: InvestigationStep, index: number) {
    if (!activeWorkspace?.huntPackage) return;
    setHelpStep(step);
    setStruggle(
      [
        `Current step: ${step.title}`,
        `Step summary: ${step.description}`,
        `Evidence to check: ${compactList(step.expected_evidence, 5).join(", ") || "not specified"}`,
        `Completed steps: ${completedStepTitles(activeWorkspace).join(", ") || "none yet"}`,
        `Warning: ${activeWorkspace.huntPackage.warning_preview?.message || "not available"}`,
      ].join("\n")
    );
    setQuestion("");
    setSupervisorError("");
    setIsSupervisorSubmitted(false);
    setIsSupervisorModalOpen(true);
  }

  async function handleSendEscalation() {
    if (!activeWorkspace?.huntPackage) return;
    const packageData = activeWorkspace.huntPackage;
    try {
      await sendWarningEvent(
        packageData.package_id,
        packageData.report_title,
        "escalation_warning",
        packageData.severity_hint,
        packageData.confidence_score,
        {
          escalation_condition: packageData.escalation_condition,
          correlation_logic: packageData.correlation_logic,
          confirmed_evidence: compactList([
            ...packageData.required_telemetry,
            ...packageData.key_behaviors,
            ...packageData.hunt_checklist,
          ], 8),
        }
      );
      updateWorkspace(activeWorkspace.id, { escalationSent: true, message: "Escalation warning sent to Discord ticket." });
      void refreshCases();
    } catch (error) {
      updateWorkspace(activeWorkspace.id, {
        status: "error",
        message: error instanceof Error ? error.message : "Cannot send escalation warning",
      });
    }
  }

  async function handleEndCase() {
    if (!activeWorkspace?.huntPackage) return;
    const packageData = activeWorkspace.huntPackage;
    try {
      await sendWarningEvent(
        packageData.package_id,
        packageData.report_title,
        "final_summary",
        packageData.severity_hint,
        packageData.confidence_score,
        {
          summary: packageData.threat_summary,
          completed_steps: completedStepTitles(activeWorkspace),
          evidence_reviewed: compactList([
            ...packageData.required_telemetry,
            ...packageData.key_behaviors,
            ...packageData.false_positive_checks,
          ], 8),
          recommended_response: packageData.recommended_response,
        }
      );
      updateWorkspace(activeWorkspace.id, { finalSummarySent: true, message: "Final summary sent to Discord ticket." });
      void refreshCases();
    } catch (error) {
      updateWorkspace(activeWorkspace.id, {
        status: "error",
        message: error instanceof Error ? error.message : "Cannot send final summary",
      });
    }
  }

  async function handleSupervisorSubmit() {
    if (!activeWorkspace?.huntPackage) return;
    setIsSubmittingSupervisor(true);
    setSupervisorError("");
    try {
      await askSupervisor(
        activeWorkspace.huntPackage.package_id,
        activeWorkspace.huntPackage.report_title,
        struggle,
        question,
        buildSupervisorContext(activeWorkspace.huntPackage, helpStep, completedStepTitles(activeWorkspace))
      );
      setIsSupervisorSubmitted(true);
      void refreshCases();
      setTimeout(() => {
        setIsSupervisorModalOpen(false);
        setIsSupervisorSubmitted(false);
        setHelpStep(undefined);
      }, 1000);
    } catch (error) {
      setSupervisorError(error instanceof Error ? error.message : "Failed to notify supervisor");
    } finally {
      setIsSubmittingSupervisor(false);
    }
  }

  async function handleLogin(email: string, password: string) {
    setAuthLoading(true);
    setAuthError("");
    try {
      await signInWithEmailAndPassword(firebaseAuth, email, password);
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Cannot sign in with this account");
    } finally {
      setAuthLoading(false);
    }
  }

  async function handleLogout() {
    await signOut(firebaseAuth);
    setReports([]);
    setNotifications([]);
    setWorkspaces([createWorkspace(1)]);
  }

  async function handleDismissNotification(notificationId: string) {
    setNotifications((items) =>
      items.map((item) => (item.notification_id === notificationId ? { ...item, read: true } : item))
    );
    try {
      await markNotificationRead(notificationId);
    } catch (error) {
      console.error("Failed to mark notification read:", error);
    }
  }

  const selectedReport = reports.find((report) => report.slug === activeWorkspace?.selectedSlug);

  if (!authReady) {
    return (
      <main className="login-shell">
        <section className="login-panel compact">
          <Loader2 className="spin" size={24} />
          <p>Preparing authentication...</p>
        </section>
      </main>
    );
  }

  if (!authUser) {
    return <LoginScreen onLogin={handleLogin} error={authError} loading={authLoading} />;
  }

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

        <div className="auth-card">
          <span>Signed in</span>
          <strong>{authUser.email}</strong>
          <button type="button" onClick={() => void handleLogout()}>Logout</button>
        </div>

        <NotificationPanel
          notifications={notifications}
          onDismiss={(id) => void handleDismissNotification(id)}
          onOpenCase={(caseId) => void openCase(caseId)}
        />

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

        <div className="sidebar-tabs" aria-label="Report workspace navigation">
          <button
            className={sidebarMode === "processing" ? "sidebar-tab active" : "sidebar-tab"}
            onClick={() => setSidebarMode("processing")}
            type="button"
          >
            Processing report
          </button>
          <button
            className={sidebarMode === "history" ? "sidebar-tab active" : "sidebar-tab"}
            onClick={() => {
              setSidebarMode("history");
              void refreshCases();
            }}
            type="button"
          >
            Recent cases
          </button>
          <button
            className={sidebarMode === "search" ? "sidebar-tab active" : "sidebar-tab"}
            onClick={() => setSidebarMode("search")}
            type="button"
          >
            Search case
          </button>
        </div>

        {sidebarMode === "processing" ? (
          <div className="processing-pane">
            <div className="processing-heading">
              <span className="field-label">Open reports</span>
              <button className="icon-button" onClick={addWorkspace} type="button" aria-label="Add processing report">
                <Plus size={17} />
              </button>
            </div>
            <div className="processing-list" aria-label="Processing reports">
              {workspaces.map((workspace) => (
                <button
                  className={workspace.id === activeWorkspace?.id ? "processing-item selected" : "processing-item"}
                  key={workspace.id}
                  onClick={() => setActiveWorkspaceId(workspace.id)}
                  type="button"
                >
                  <span className="case-name">{workspace.name}</span>
                  <span className="case-meta">
                    <span>{workspace.huntPackage ? "hunt package ready" : "draft input"}</span>
                    <span>{workspace.status === "loading" ? "processing" : workspace.status}</span>
                  </span>
                </button>
              ))}
            </div>
          </div>
        ) : sidebarMode === "history" ? (
          <div className="processing-pane">
            <div className="processing-heading">
              <span className="field-label">Recent cases</span>
              <button className="workflow-button secondary" onClick={() => void refreshCases()} type="button">
                Refresh
              </button>
            </div>
            <div className="processing-list" aria-label="Recent cases">
              {cases.length ? (
                cases.map((item) => (
                  <button
                    className="processing-item"
                    key={item.case_id}
                    onClick={() => void openCase(item.case_id)}
                    type="button"
                  >
                    <span className="case-name">{item.title || item.case_id}</span>
                    <span className="case-meta">
                      <span className={severityClass(item.severity || "")}>{item.severity || "unknown"}</span>
                      <span>{item.status || "open"}</span>
                      {item.unread_notifications ? <span>{item.unread_notifications} unread</span> : null}
                    </span>
                  </button>
                ))
              ) : (
                <p className="notification-empty">No case history yet.</p>
              )}
            </div>
          </div>
        ) : (
          <>
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
                  className={report.slug === activeWorkspace?.selectedSlug ? "case-item selected" : "case-item"}
                  key={report.slug}
                  onClick={() => void loadSample(report.slug)}
                  type="button"
                >
                  <span className="case-name">{report.alert_name}</span>
                  <span className="case-meta">
                    <span className={severityClass(report.severity)}>{report.severity}</span>
                    <span>{report.alert_source}</span>
                  </span>
                </button>
              ))}
            </div>
          </>
        )}
      </aside>

      {activeWorkspace && (
        <section className="workspace">
          <div className="input-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Threat report input</p>
                <h2>{selectedReport ? selectedReport.alert_name : activeWorkspace.name}</h2>
              </div>
              <button className="primary-button" onClick={() => void analyze()} disabled={activeWorkspace.status === "loading"} type="button">
                {activeWorkspace.status === "loading" ? <Loader2 className="spin" size={18} /> : <Play size={18} />}
                Analyze
              </button>
            </div>

            <div className="title-row">
              <label className="field-label" htmlFor="report-title">Title</label>
              <input
                id="report-title"
                value={activeWorkspace.title}
                onChange={(event) => updateActiveWorkspace({ title: event.target.value, name: event.target.value || "Untitled report" })}
                placeholder="Alert or report title"
              />
            </div>

            <textarea
              value={activeWorkspace.content}
              onChange={(event) => updateActiveWorkspace({ content: event.target.value })}
              placeholder="Paste threat report, alert context, or advisory text here."
            />

            {activeWorkspace.message && (
              <div className={activeWorkspace.status === "error" ? "status-line error" : "status-line"}>
                {activeWorkspace.status === "ready" ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
                {activeWorkspace.message}
              </div>
            )}
          </div>

          <div className="output-panel">
            {activeWorkspace.huntPackage ? (
              <HuntPackageView
                huntPackage={activeWorkspace.huntPackage}
                priorityConfirmed={activeWorkspace.priorityConfirmed}
                workedStepIds={activeWorkspace.workedStepIds}
                escalationSent={activeWorkspace.escalationSent}
                finalSummarySent={activeWorkspace.finalSummarySent}
                timeline={activeWorkspace.timeline}
                onConfirmPriority={() => void handleConfirmPriority()}
                onStartStep={(step, index) => void handleStartStep(step, index)}
                onAskForHelp={handleAskForHelpStep}
                onSendEscalation={() => void handleSendEscalation()}
                onEndCase={() => void handleEndCase()}
              />
            ) : (
              <EmptyResult />
            )}
          </div>
        </section>
      )}

      {isSupervisorModalOpen && activeWorkspace?.huntPackage && (
        <div className="supervisor-modal-overlay">
          <div className="supervisor-modal-card">
            <h2>Ask Supervisor for Help</h2>
            <p className="subtitle">
              {helpStep ? `Review and edit the summary for: ${helpStep.title}` : "Please provide details about your issue below."}
            </p>
            
            <form onSubmit={(e) => { e.preventDefault(); void handleSupervisorSubmit(); }}>
              <div className="form-group">
                <label htmlFor="struggling-with">Current situation summary</label>
                <textarea
                  id="struggling-with"
                  value={struggle}
                  onChange={(e) => setStruggle(e.target.value)}
                  placeholder="Summarize current step, evidence checked, completed work, and what is unclear..."
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="specific-question">Your question</label>
                <input
                  id="specific-question"
                  type="text"
                  value={question}
                  onChange={(e) => setQuestion(e.target.value)}
                  placeholder="Ask your specific question here..."
                  required
                />
              </div>

              {supervisorError && <p className="error-text">{supervisorError}</p>}

              <div className="form-actions">
                <button
                  type="button"
                  className="cancel-button"
                  onClick={() => setIsSupervisorModalOpen(false)}
                  disabled={isSubmittingSupervisor || isSupervisorSubmitted}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className={`submit-button ${isSupervisorSubmitted ? "submitted" : ""}`}
                  disabled={isSubmittingSupervisor || isSupervisorSubmitted}
                >
                  {isSupervisorSubmitted ? "Submitted!" : isSubmittingSupervisor ? "Submitting..." : "Submit"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </main>
  );
}

