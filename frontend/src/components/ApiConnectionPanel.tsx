import { useEffect, useState } from "react";
import { describeApiBaseUrl } from "../apiConfig";

interface ApiConnectionPanelProps {
  apiBaseUrl: string;
  description: string;
  statusLabel: string;
  statusTone: "completed" | "failed" | "pending" | "idle";
  title: string;
  onApply: (value: string) => void;
}

export default function ApiConnectionPanel({
  apiBaseUrl,
  description,
  statusLabel,
  statusTone,
  title,
  onApply,
}: ApiConnectionPanelProps) {
  const [draft, setDraft] = useState(apiBaseUrl);

  useEffect(() => {
    setDraft(apiBaseUrl);
  }, [apiBaseUrl]);

  return (
    <section className="panel connection-panel">
      <div className="section-heading">
        <div>
          <p className="eyebrow">API endpoint</p>
          <h2>{title}</h2>
        </div>
        <div className={`status-chip status-${statusTone}`}>{statusLabel}</div>
      </div>
      <p className="hero-body">{description}</p>
      <div className="field-grid field-grid-2">
        <label className="field">
          <span className="field-label">Base URL</span>
          <input
            aria-label="API base URL"
            className="text-input"
            onChange={(event) => setDraft(event.target.value)}
            placeholder="https://api.example.com"
            value={draft}
          />
          <span className="field-hint">
            Leave this empty when the frontend is served by `knives-out serve`. Use an absolute
            URL for GitHub Pages or other static hosts.
          </span>
        </label>
        <div className="connection-meta">
          <div className="summary-card">
            <span>Current endpoint</span>
            <strong>{describeApiBaseUrl(apiBaseUrl)}</strong>
          </div>
          <div className="action-row">
            <button className="secondary-button" onClick={() => onApply(draft)} type="button">
              Save endpoint
            </button>
            <button className="ghost-button" onClick={() => onApply("")} type="button">
              Use same origin
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}
