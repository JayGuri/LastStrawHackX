const INSIGHTS_BASE_URL = import.meta.env.VITE_INSIGHTS_API_URL;
const RISK_BASE_URL = import.meta.env.VITE_RISK_API_URL;
const LIFELINE_BASE_URL = import.meta.env.VITE_LIFELINE_API_URL;

async function request(baseUrl, method, path, body) {
  try {
    const options = {
      method,
      headers: { "Content-Type": "application/json" },
    };
    if (body !== undefined) {
      options.body = JSON.stringify(body);
    }
    const res = await fetch(`${baseUrl}${path}`, options);
    if (!res.ok) {
      let message = `HTTP ${res.status}`;
      try {
        const text = await res.text();
        try {
          const json = JSON.parse(text);
          message = json?.detail ?? json?.error ?? message;
        } catch {
          message = text || message;
        }
      } catch {
        // failed to read text
      }
      return { data: null, error: message };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err) {
    return { data: null, error: err?.message ?? "Network error" };
  }
}

export const insightsApi = {
  /** POST /analyze — Trigger a new analysis run */
  analyze(payload) {
    return request(INSIGHTS_BASE_URL, "POST", "/analyze", payload);
  },

  /** POST /analyze/risk — Trigger a new risk analysis */
  analyzeRisk(payload) {
    return request(RISK_BASE_URL, "POST", "/analyze/risk", payload);
  },

  /** POST /flood-infrastructure — Lifeline Engine */
  analyzeLifeline(payload) {
    return request(LIFELINE_BASE_URL, "POST", "/flood-infrastructure", payload);
  },

  /** GET /runs — Fetch all historical runs */
  getRuns() {
    return request(INSIGHTS_BASE_URL, "GET", "/runs");
  },

  /** GET /runs/{run_id} — Fetch full detail for one run */
  getRunDetail(runId) {
    return request(INSIGHTS_BASE_URL, "GET", `/runs/${runId}`);
  },
};
