import React, { useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Legend,
} from "recharts";
import { useInsightsStore } from "../stores/insightsStore.js";
import { RISK_COLORS } from "../data/districts.js";
import RiskBadge from "../components/common/RiskBadge.jsx";
import StatCounter from "../components/common/StatCounter.jsx";
import GeoSearchInput from "../components/ui/GeoSearchInput.jsx";
import CalendarPicker from "../components/ui/CalendarPicker.jsx";
import { geocodeApi } from "../api/geocodeApi.js";
import { generateInsightsReport } from "../utils/reports/generateInsightsReport.js";
import { useAppStore } from "../stores/appStore.js";

// ── Sub-Component: DataSourceBadge ──────────────────────────
function DataSourceBadge() {
  return (
    <div
      className="inline-flex items-center gap-2 px-3 py-1.5"
      style={{
        background: "rgba(74,176,216,0.06)",
        border: "1px solid rgba(74,176,216,0.2)",
      }}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-ice animate-pulse" />
      <span
        className="font-mono text-[9px] tracking-widest uppercase"
        style={{ color: "#4ab0d8" }}
      >
        NASA/ESA Sentinel-1 SAR · Google Earth Engine
      </span>
    </div>
  );
}

// ── Sub-Component: RunRow ──────────────────────────────────
function RunRow({ run, isSelected, onClick, index }) {
  const riskColor = RISK_COLORS[run.risk_label]?.hex ?? "#ece8df";
  return (
    <motion.button
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.04 }}
      onClick={onClick}
      className="w-full text-left px-4 py-3 border-b transition-colors"
      style={{
        borderColor: "rgba(242,209,109,0.08)",
        background: isSelected ? "rgba(242,209,109,0.05)" : "transparent",
        borderLeft: isSelected ? "2px solid #f2d16d" : "2px solid transparent",
      }}
      onMouseEnter={(e) => {
        if (!isSelected)
          e.currentTarget.style.background = "rgba(236,232,223,0.03)";
      }}
      onMouseLeave={(e) => {
        if (!isSelected) e.currentTarget.style.background = "transparent";
      }}
    >
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-[10px]">
        <div
          className="font-mono tracking-widest uppercase"
          style={{ color: "#ece8df" }}
        >
          {run.location_name?.split(",")[0] ?? "Unknown"}
        </div>
        <div
          className="font-mono text-[9px]"
          style={{ color: "rgba(236,232,223,0.6)" }}
        >
          {new Date(run.timestamp).toLocaleDateString()}
        </div>
        <div className="font-mono text-[9px]" style={{ color: "#d4900a" }}>
          {run.severity}
        </div>
        <div>
          <RiskBadge risk={run.risk_label} size="xs" showDot={false} />
        </div>
        <div
          className="font-mono text-[9px] text-right"
          style={{ color: "#f2d16d" }}
        >
          {run.flood_area_km2?.toFixed(0)} km²
        </div>
      </div>
    </motion.button>
  );
}

// ── Sub-Component: StatCard ────────────────────────────────
function StatCard({
  label,
  value,
  unit = "",
  decimals = 0,
  color = "#ece8df",
  isText = false,
  customContent = null,
  isGrayed = false,
}) {
  return (
    <div
      className="p-4 flex flex-col justify-between"
      style={{
        background: "#0a0907",
        border: "1px solid rgba(242,209,109,0.15)",
        minHeight: 80,
      }}
    >
      <span
        className="font-mono text-[8px] uppercase tracking-[0.25em] mb-2"
        style={{ color: "rgba(242,209,109,0.5)" }}
      >
        {label}
      </span>
      <div className={isGrayed ? "opacity-50 grayscale" : ""}>
        {customContent ??
          (isText ?
            <span
              className="font-mono text-sm tracking-widest uppercase"
              style={{ color }}
            >
              {value}
            </span>
          : <span
              className="font-mono text-lg tracking-widest"
              style={{ color }}
            >
              <StatCounter
                target={value ?? 0}
                decimals={decimals}
                suffix={unit}
              />
            </span>)}
      </div>
    </div>
  );
}

// ── Sub-Component: NoiseWarningBanner ──────────────────────
function NoiseWarningBanner({ reason }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: -8 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex items-start gap-3 px-4 py-3"
      style={{
        background: "rgba(200,160,24,0.06)",
        border: "1px solid rgba(200,160,24,0.2)",
        borderLeft: "3px solid #c8a018",
      }}
    >
      <span className="text-xl flex-shrink-0">⚠</span>
      <div className="flex-1">
        <div
          className="font-mono text-[10px] uppercase tracking-widest mb-1"
          style={{ color: "#c8a018" }}
        >
          Signal Quality Warning
        </div>
        <div
          className="font-mono text-[9px]"
          style={{ color: "rgba(236,232,223,0.6)" }}
        >
          {reason ||
            "Data may contain noise artifacts. Interpret statistics with caution."}
        </div>
      </div>
    </motion.div>
  );
}

// ── Sub-Component: ProcessingTimeBadge ──────────────────────
function ProcessingTimeBadge({ seconds }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: -8 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex items-center gap-2 px-3 py-2"
      style={{
        background: "rgba(56,160,88,0.06)",
        border: "1px solid rgba(56,160,88,0.2)",
        borderLeft: "3px solid #38a058",
      }}
    >
      <span
        className="font-mono text-[9px] uppercase tracking-widest"
        style={{ color: "#38a058" }}
      >
        ✓ Pipeline completed in {seconds.toFixed(1)}s
      </span>
    </motion.div>
  );
}

// ── Sub-Component: ConfidenceCard ──────────────────────────
function ConfidenceCard({ data, isGrayed }) {
  const confColor =
    data.confidence === "High" ? "#38a058"
    : data.confidence === "Medium" ? "#c8a018"
    : "#d84040";
  return (
    <div
      className={`p-4 flex flex-col justify-between ${isGrayed ? "opacity-50" : ""}`}
      style={{
        background: "#0a0907",
        border: "1px solid rgba(242,209,109,0.15)",
        minHeight: 80,
      }}
    >
      <span
        className="font-mono text-[8px] uppercase tracking-[0.25em] mb-2"
        style={{ color: "rgba(242,209,109,0.5)" }}
      >
        Signal Confidence
      </span>
      <div>
        <div
          className="font-mono text-sm tracking-widest uppercase mb-2"
          style={{ color: confColor }}
        >
          {data.confidence}
        </div>
        <div
          className="font-mono text-[8px] leading-relaxed"
          style={{ color: "rgba(236,232,223,0.5)" }}
        >
          {data.reason ?? "N/A"}
        </div>
      </div>
    </div>
  );
}

// ── Sub-Component: DepthCard ───────────────────────────────
function DepthCard({ data, isGrayed }) {
  return (
    <div
      className={`p-4 flex flex-col justify-between ${isGrayed ? "opacity-50" : ""}`}
      style={{
        background: "#0a0907",
        border: "1px solid rgba(242,209,109,0.15)",
        minHeight: 80,
      }}
    >
      <span
        className="font-mono text-[8px] uppercase tracking-[0.25em] mb-2"
        style={{ color: "rgba(242,209,109,0.5)" }}
      >
        Depth Proxy
      </span>
      <div>
        <div
          className="font-mono text-sm tracking-widest uppercase mb-1"
          style={{ color: "#4ab0d8" }}
        >
          {data.depth_category}
        </div>
        <div
          className="font-mono text-[9px]"
          style={{ color: "rgba(236,232,223,0.6)" }}
        >
          {data.mean_db_drop.toFixed(2)} dB
        </div>
      </div>
    </div>
  );
}

// ── Sub-Component: ChangeDetectionImage ────────────────────
function ChangeDetectionImage({ src, location, bbox, resolution }) {
  const [loaded, setLoaded] = React.useState(false);
  const [error, setError] = React.useState(false);

  const bboxString =
    Array.isArray(bbox) ? bbox.map((n) => n.toFixed(2)).join(", ") : null;

  return (
    <div
      className="relative overflow-hidden"
      style={{ border: "1px solid rgba(242,209,109,0.15)" }}
    >
      <div
        className="px-4 py-2 border-b flex items-center justify-between"
        style={{
          borderColor: "rgba(242,209,109,0.15)",
          background: "rgba(242,209,109,0.03)",
        }}
      >
        <span
          className="font-mono text-[9px] uppercase tracking-[0.3em]"
          style={{ color: "#f2d16d" }}
        >
          SAR Change Detection Panel
        </span>
        {resolution && (
          <span
            className="font-mono text-[8px] tracking-widest"
            style={{ color: "rgba(236,232,223,0.4)" }}
          >
            {typeof resolution === "number" ?
              resolution.toFixed(0)
            : resolution}
            M RES
          </span>
        )}
      </div>

      <div className="relative bg-black" style={{ minHeight: 240 }}>
        {!loaded && !error && (
          <div className="absolute inset-0 flex items-center justify-center shimmer">
            <span
              className="font-mono text-[9px] uppercase tracking-widest"
              style={{ color: "rgba(236,232,223,0.2)" }}
            >
              Loading imagery...
            </span>
          </div>
        )}
        {error && (
          <div
            className="absolute inset-0 flex items-center justify-center"
            style={{ background: "rgba(216,64,64,0.04)" }}
          >
            <span
              className="font-mono text-[9px] uppercase tracking-widest"
              style={{ color: "rgba(216,64,64,0.6)" }}
            >
              Image unavailable
            </span>
          </div>
        )}
        {src && !error && (
          <img
            src={src}
            alt={`SAR change detection for ${location}`}
            className={`w-full object-contain transition-opacity duration-300 ${loaded ? "opacity-100" : "opacity-0"}`}
            onLoad={() => setLoaded(true)}
            onError={() => setError(true)}
          />
        )}
      </div>

      <div
        className="px-4 py-2 border-t"
        style={{ borderColor: "rgba(242,209,109,0.1)" }}
      >
        <span
          className="font-mono text-[8px] uppercase tracking-widest"
          style={{ color: "rgba(236,232,223,0.4)" }}
        >
          {location}
          {bboxString && ` · bbox [${bboxString}]`}
        </span>
      </div>
    </div>
  );
}

// ── Sub-Component: PatchTable ──────────────────────────────
function PatchTable({ patches = [], isGrayed }) {
  return (
    <div
      className={`${isGrayed ? "opacity-50" : ""}`}
      style={{ border: "1px solid rgba(242,209,109,0.15)" }}
    >
      <div
        className="px-4 py-2 border-b grid grid-cols-5 gap-2"
        style={{
          borderColor: "rgba(242,209,109,0.15)",
          background: "rgba(242,209,109,0.03)",
        }}
      >
        {["Patch", "Area km²", "Lat", "Lon", "Risk"].map((h) => (
          <span
            key={h}
            className="font-mono text-[8px] uppercase tracking-[0.2em]"
            style={{ color: "rgba(242,209,109,0.5)" }}
          >
            {h}
          </span>
        ))}
      </div>
      {patches.map((patch, i) => (
        <motion.div
          key={patch.patch_id}
          initial={{ opacity: 0, x: -4 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: i * 0.06 }}
          className="px-4 py-3 grid grid-cols-5 gap-2 border-b"
          style={{ borderColor: "rgba(242,209,109,0.06)" }}
        >
          <span className="font-mono text-[10px]" style={{ color: "#ece8df" }}>
            #{String(patch.patch_id).padStart(3, "0")}
          </span>
          <span className="font-mono text-[10px]" style={{ color: "#f2d16d" }}>
            {patch.area_km2.toFixed(2)}
          </span>
          <span
            className="font-mono text-[10px]"
            style={{ color: "rgba(236,232,223,0.6)" }}
          >
            {patch.centroid_lat.toFixed(4)}
          </span>
          <span
            className="font-mono text-[10px]"
            style={{ color: "rgba(236,232,223,0.6)" }}
          >
            {patch.centroid_lon.toFixed(4)}
          </span>
          <RiskBadge risk={patch.risk_label} size="xs" showDot={false} />
        </motion.div>
      ))}
    </div>
  );
}

// ── Sub-Component: SimpleMarkdown ──────────────────────────
function SimpleMarkdown({ text }) {
  const lines = (text ?? "").split("\n");
  return (
    <div className="space-y-0.5">
      {lines.map((line, i) => {
        const headerMatch = line.match(/^\* \*\*(.+?)\*\*:?/);
        const bulletMatch = line.match(/^\s{2,}\* (.+)/);
        if (headerMatch) {
          return (
            <p
              key={i}
              className="font-mono text-[10px] tracking-[0.2em] uppercase mt-4 mb-1 first:mt-0"
              style={{ color: "#f2d16d" }}
            >
              {headerMatch[1]}
            </p>
          );
        }
        if (bulletMatch) {
          return (
            <div
              key={i}
              className="flex gap-2 pl-3 text-[13px] leading-relaxed"
              style={{ color: "rgba(191,207,216,0.8)" }}
            >
              <span style={{ color: "rgba(242,209,109,0.5)", flexShrink: 0 }}>
                ›
              </span>
              <span>{bulletMatch[1]}</span>
            </div>
          );
        }
        if (line.trim() === "") return <div key={i} className="h-1" />;
        return (
          <p
            key={i}
            className="text-[13px]"
            style={{ color: "rgba(191,207,216,0.6)" }}
          >
            {line}
          </p>
        );
      })}
    </div>
  );
}

// ── Sub-Component: LocationTrendChart ─────────────────────────────
function LocationTrendChart({ locationRuns }) {
  const CustomTooltip = ({ active, payload }) => {
    if (!active || !payload?.length) return null;
    return (
      <div
        className="bg-[#0a0907] border rounded-lg px-3 py-2 text-xs font-mono"
        style={{ borderColor: "rgba(242,209,109,0.3)" }}
      >
        {payload.map((entry, idx) => (
          <div key={idx} style={{ color: entry.color }}>
            {entry.name}: {entry.value.toFixed(1)}
          </div>
        ))}
      </div>
    );
  };

  const chartData = locationRuns
    .slice()
    .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
    .map((run) => ({
      date: new Date(run.timestamp).toLocaleDateString("en", {
        month: "short",
        day: "numeric",
      }),
      floodArea: run.flood_area_km2 ?? 0,
      floodPct: run.flood_percentage ?? 0,
    }));

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      style={{
        border: "1px solid rgba(242,209,109,0.15)",
        borderRadius: "6px",
        padding: "16px",
        background: "rgba(242,209,109,0.03)",
      }}
    >
      <div
        className="text-[9px] font-mono uppercase tracking-[0.3em] mb-4"
        style={{ color: "rgba(242,209,109,0.6)" }}
      >
        Location Trend
      </div>
      <ResponsiveContainer width="100%" height={200}>
        <LineChart
          data={chartData}
          margin={{ top: 8, right: 20, left: -10, bottom: 20 }}
        >
          <CartesianGrid
            strokeDasharray="3 3"
            stroke="rgba(242,209,109,0.08)"
          />
          <XAxis
            dataKey="date"
            tick={{
              fontSize: 11,
              fontFamily: "JetBrains Mono",
              fill: "rgba(236,232,223,0.4)",
            }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis
            yAxisId="left"
            tick={{
              fontSize: 11,
              fontFamily: "JetBrains Mono",
              fill: "rgba(236,232,223,0.4)",
            }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis
            yAxisId="right"
            orientation="right"
            tick={{
              fontSize: 11,
              fontFamily: "JetBrains Mono",
              fill: "rgba(236,232,223,0.4)",
            }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip content={<CustomTooltip />} />
          <Legend
            iconType="line"
            wrapperStyle={{
              fontSize: "11px",
              fontFamily: "JetBrains Mono",
              color: "rgba(236,232,223,0.6)",
              paddingTop: "16px",
            }}
          />
          <Line
            yAxisId="left"
            type="monotone"
            dataKey="floodArea"
            stroke="#d4900a"
            strokeWidth={2}
            dot={{ r: 4, fill: "#d4900a" }}
            activeDot={{ r: 6, fill: "#d4900a" }}
            name="Flood Area (km²)"
          />
          <Line
            yAxisId="right"
            type="monotone"
            dataKey="floodPct"
            stroke="#4ab0d8"
            strokeWidth={2}
            dot={{ r: 4, fill: "#4ab0d8" }}
            activeDot={{ r: 6, fill: "#4ab0d8" }}
            name="Flood % "
          />
        </LineChart>
      </ResponsiveContainer>
    </motion.div>
  );
}

// ── Sub-Component: AnalyzeForm ─────────────────────────────
function AnalyzeForm({ onSubmit, isLoading }) {
  const [location, setLocation] = React.useState("");
  const [locationResults, setLocationResults] = React.useState([]);
  const [searchingLocation, setSearchingLocation] = React.useState(false);
  const locationDebounce = React.useRef(null);

  const [preStart, setPreStart] = React.useState("");
  const [preEnd, setPreEnd] = React.useState("");
  const [postStart, setPostStart] = React.useState("");
  const [postEnd, setPostEnd] = React.useState("");

  const showNotification = useAppStore((s) => s.showNotification);

  const searchLocation = React.useCallback(async (q) => {
    clearTimeout(locationDebounce.current);
    if (q.length < 2) {
      setLocationResults([]);
      return;
    }
    locationDebounce.current = setTimeout(async () => {
      setSearchingLocation(true);
      const { data } = await geocodeApi.search(q, { limit: 6 });
      setLocationResults(data ?? []);
      setSearchingLocation(false);
    }, 280);
  }, []);

  const handleSelectLocation = (item) => {
    // Keep City and Country to ensure accurate geocoding on the backend
    const parts = item.display_name.split(",");
    const primary =
      parts.length > 1 ?
        `${parts[0].trim()}, ${parts[parts.length - 1].trim()}`
      : parts[0].trim();
    setLocation(primary);
    setLocationResults([]);
  };

  const handleSubmit = (e) => {
    e.preventDefault();

    if (!location || !preStart || !preEnd || !postStart || !postEnd) {
      showNotification("All fields are required", "warning");
      return;
    }

    // Satellite Data Lag Check (approx 4 days)
    const lagDays = 4;
    const today = new Date();
    const limitDate = new Date(today.setDate(today.getDate() - lagDays));

    const checkDate = (dString) => new Date(dString) > limitDate;

    if (
      checkDate(preStart) ||
      checkDate(preEnd) ||
      checkDate(postStart) ||
      checkDate(postEnd)
    ) {
      showNotification(
        `Satellite imagery has a ${lagDays}-day processing lag. Please select dates older than ${limitDate.toLocaleDateString()}.`,
        "warning",
      );
      return;
    }

    // Minimum Window Width Check (15 days for reliable satellite revisit)
    const minWindowDays = 15;
    const getDiffDays = (start, end) => {
      const s = new Date(start);
      const e = new Date(end);
      return Math.ceil(Math.abs(e - s) / (1000 * 60 * 60 * 24));
    };

    if (getDiffDays(preStart, preEnd) < minWindowDays) {
      showNotification(
        `Pre-event window must be at least ${minWindowDays} days for reliable satellite coverage.`,
        "warning",
      );
      return;
    }
    if (getDiffDays(postStart, postEnd) < minWindowDays) {
      showNotification(
        `Post-event window must be at least ${minWindowDays} days for reliable satellite coverage.`,
        "warning",
      );
      return;
    }

    onSubmit({ location, preStart, preEnd, postStart, postEnd });
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="p-5 flex flex-col gap-5"
      style={{
        background: "#0a0907",
        border: "1px solid rgba(242,209,109,0.15)",
      }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between border-b pb-3"
        style={{ borderColor: "rgba(242,209,109,0.15)" }}
      >
        <span
          className="text-[9px] font-mono tracking-[0.3em] uppercase"
          style={{ color: "rgba(242,209,109,0.6)" }}
        >
          New Analysis
        </span>
      </div>

      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        {/* Location */}
        <GeoSearchInput
          label="Location"
          placeholder="e.g. Larkana, Pakistan"
          value={location}
          onChange={(q) => {
            setLocation(q);
            searchLocation(q);
          }}
          results={locationResults}
          onSelect={handleSelectLocation}
          isSearching={searchingLocation}
          onClear={() => {
            setLocation("");
            setLocationResults([]);
          }}
        />

        {/* Pre-Event Window */}
        <div>
          <label
            className="text-[10px] uppercase font-mono tracking-[0.2em] mb-2 block"
            style={{ color: "rgba(236,232,223,0.5)" }}
          >
            Pre-Event Window
          </label>
          <div className="grid grid-cols-2 gap-3">
            <CalendarPicker label="" value={preStart} onChange={setPreStart} />
            <CalendarPicker label="" value={preEnd} onChange={setPreEnd} />
          </div>
        </div>

        {/* Post-Event Window */}
        <div>
          <label
            className="text-[10px] uppercase font-mono tracking-[0.2em] mb-2 block"
            style={{ color: "rgba(236,232,223,0.5)" }}
          >
            Post-Event Window
          </label>
          <div className="grid grid-cols-2 gap-3">
            <CalendarPicker
              label=""
              value={postStart}
              onChange={setPostStart}
            />
            <CalendarPicker label="" value={postEnd} onChange={setPostEnd} />
          </div>
        </div>

        {/* Submit Button */}
        <button
          type="submit"
          disabled={isLoading}
          className="relative group w-full mt-2 overflow-hidden"
          style={{
            padding: "0.8rem 1rem",
            cursor: isLoading ? "not-allowed" : "pointer",
            opacity: isLoading ? 0.5 : 1,
          }}
        >
          <span
            className="absolute inset-0 transition-colors"
            style={{ border: "1px solid rgba(242,209,109,0.4)" }}
          />
          <span
            className="absolute inset-0 translate-x-full group-hover:translate-x-0 transition-transform duration-300"
            style={{ background: "#f2d16d" }}
          />

          <span
            className="relative z-10 flex items-center justify-center gap-2 font-mono tracking-[0.2em] uppercase transition-colors text-[#f2d16d] group-hover:text-[#0a0907]"
            style={{ fontSize: "0.65rem" }}
          >
            {isLoading ?
              <>
                <span className="w-1.5 h-1.5 bg-[#f2d16d] group-hover:bg-[#0a0907] animate-pulse" />
                Analyzing...
              </>
            : "Start Analysis"}
          </span>
        </button>
      </form>
    </motion.div>
  );
}

// ── Sub-Component: AIInsightPanel ────────────────────────────
function AIInsightPanel({ selectedRun }) {
  if (!selectedRun?.ai_insight) return null;

  const { ai_insight, risk_label, severity } = selectedRun;
  const riskColor = RISK_COLORS[risk_label]?.hex || "#d4900a";

  // Parse text for formatting (**, *, etc.)
  const parseInsight = (text) => {
    if (!text) return [];
    const lines = text.split("\n").filter((l) => l.trim());
    return lines.map((line, idx) => {
      const trimmed = line.trim();
      const isBold = trimmed.startsWith("**") && trimmed.endsWith("**");
      const content = isBold ? trimmed.slice(2, -2) : trimmed;
      return { key: idx, content, isBold };
    });
  };

  const parsedLines = parseInsight(ai_insight);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.1 }}
      style={{
        border: `1px solid ${riskColor}40`,
        borderRadius: "6px",
        overflow: "hidden",
        background: `${riskColor}08`,
      }}
    >
      {/* Header */}
      <div
        className="px-4 py-3 border-b flex items-center gap-3"
        style={{ borderColor: `${riskColor}20`, background: `${riskColor}12` }}
      >
        <div
          className="w-8 h-8 rounded flex items-center justify-center"
          style={{ background: `${riskColor}20` }}
        >
          <span style={{ fontSize: "16px" }}>🔍</span>
        </div>
        <div className="flex-1">
          <div
            className="text-[11px] font-mono uppercase tracking-widest"
            style={{ color: riskColor }}
          >
            AI Analysis Report
          </div>
          <div
            className="text-[9px] font-mono"
            style={{ color: "rgba(236,232,223,0.4)" }}
          >
            {severity} flood event · {risk_label} risk
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="px-4 py-4 space-y-3">
        {parsedLines.length > 0 ?
          parsedLines.map((line) => (
            <p
              key={line.key}
              className={`font-mono text-[13px] leading-relaxed ${line.isBold ? "font-bold" : ""}`}
              style={{
                color: line.isBold ? riskColor : "rgba(236,232,223,0.8)",
                lineHeight: "1.6",
              }}
            >
              {line.content}
            </p>
          ))
        : <p
            className="text-[13px] font-mono"
            style={{ color: "rgba(236,232,223,0.6)" }}
          >
            {ai_insight}
          </p>
        }
      </div>

      {/* Footer accent */}
      <div
        className="h-0.5"
        style={{
          background: `linear-gradient(90deg, ${riskColor}00, ${riskColor}80, ${riskColor}00)`,
        }}
      />
    </motion.div>
  );
}

// ── Sub-Component: AnalysisThinkingPanel ───────────────────
const THINKING_STEPS = [
  "Initializing analysis pipeline...",
  "Collecting Sentinel-1 SAR imagery...",
  "Calibrating radiometric corrections...",
  "Computing SAR backscatter difference...",
  "Detecting flood boundaries...",
  "Computing flood statistics...",
  "Assessing risk level...",
  "Formulating AI insights...",
  "Generating assessment report...",
];

function AnalysisThinkingPanel() {
  const [stepIdx, setStepIdx] = React.useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setStepIdx((i) => (i + 1) % THINKING_STEPS.length);
    }, 2200);
    return () => clearInterval(interval);
  }, []);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="flex flex-col items-center justify-center"
      style={{ minHeight: "420px" }}
    >
      {/* Animated orb / spinner */}
      <div className="relative mb-8">
        {/* outer ring */}
        <motion.div
          className="w-16 h-16 rounded-full border"
          style={{ borderColor: "rgba(242,209,109,0.3)" }}
          animate={{ rotate: 360 }}
          transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
        />
        {/* inner pulsing dot */}
        <motion.div
          className="absolute inset-0 flex items-center justify-center"
          animate={{ opacity: [0.4, 1, 0.4] }}
          transition={{ duration: 2, repeat: Infinity }}
        >
          <div
            className="w-2 h-2 rounded-full"
            style={{ background: "#f2d16d" }}
          />
        </motion.div>
      </div>

      {/* Cycling status message */}
      <div style={{ height: "24px" }} className="overflow-hidden">
        <AnimatePresence mode="wait">
          <motion.p
            key={stepIdx}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.3 }}
            className="font-mono text-[11px] text-center tracking-widest uppercase"
            style={{ color: "#f2d16d" }}
          >
            {THINKING_STEPS[stepIdx]}
          </motion.p>
        </AnimatePresence>
      </div>

      {/* Subtitle */}
      <p
        className="mt-3 font-mono text-[9px] uppercase tracking-[0.3em]"
        style={{ color: "rgba(236,232,223,0.25)" }}
      >
        SAR · Google Earth Engine · Gemini AI
      </p>
    </motion.div>
  );
}

// ── Sub-Component: LoadingSkeleton ─────────────────────────
function LoadingSkeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      <div className="grid grid-cols-4 gap-3">
        {[...Array(4)].map((_, i) => (
          <div
            key={i}
            className="h-20 rounded"
            style={{ background: "rgba(255,255,255,0.04)" }}
          />
        ))}
      </div>
      <div className="grid grid-cols-2 gap-3">
        {[...Array(2)].map((_, i) => (
          <div
            key={i}
            className="h-24 rounded"
            style={{ background: "rgba(255,255,255,0.04)" }}
          />
        ))}
      </div>
      <div
        className="h-56 rounded"
        style={{ background: "rgba(255,255,255,0.04)" }}
      />
    </div>
  );
}

// ── Sub-Component: EmptyState ──────────────────────────────
function EmptyState() {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="flex flex-col items-center justify-center py-20"
    >
      <div className="text-5xl mb-4">📊</div>
      <span
        className="font-mono text-[10px] uppercase tracking-widest"
        style={{ color: "rgba(236,232,223,0.4)" }}
      >
        Select a run from the history to view details
      </span>
    </motion.div>
  );
}

// ── Sub-Component: ErrorState ──────────────────────────────
function ErrorState({ message }) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="flex flex-col items-center justify-center py-12 px-4"
      style={{
        background: "rgba(216,64,64,0.04)",
        border: "1px solid rgba(216,64,64,0.2)",
      }}
    >
      <div className="text-2xl mb-2">⚠</div>
      <span
        className="font-mono text-[9px] uppercase tracking-widest text-center"
        style={{ color: "rgba(216,64,64,0.6)" }}
      >
        {message || "An error occurred loading data"}
      </span>
    </motion.div>
  );
}

// ── Main Component ─────────────────────────────────────────
export default function FloodInsights() {
  const {
    runs,
    runsLoading,
    runsError,
    fetchRuns,
    selectedRunId,
    selectedRun,
    detailLoading,
    detailError,
    selectRun,
  } = useInsightsStore();

  const [analyzeLoading, setAnalyzeLoading] = React.useState(false);
  const showNotification = useAppStore((s) => s.showNotification);

  useEffect(() => {
    fetchRuns();
  }, [fetchRuns]);

  // Group runs by location for temporal chart
  const runsByLocation = React.useMemo(() => {
    const map = {};
    runs.forEach((run) => {
      const key = run.location_name?.split(",")[0]?.trim() ?? "Unknown";
      if (!map[key]) map[key] = [];
      map[key].push(run);
    });
    return map;
  }, [runs]);

  // Extract available data
  const data = selectedRun ?? {};

  const handleAnalyzeSubmit = async (formData) => {
    setAnalyzeLoading(true);

    try {
      // Call the analyze endpoint from insightsApi
      const { insightsApi } = await import("../api/insightsApi.js");
      const payload = {
        location: formData.location,
        pre_start: formData.preStart,
        pre_end: formData.preEnd,
        post_start: formData.postStart,
        post_end: formData.postEnd,
        threshold: -1.25,
      };
      const { data: result, error } = await insightsApi.analyze(payload);

      if (error) {
        // Intercept generic 500 and provide context-aware help
        if (error.includes("500")) {
          showNotification(
            "Backend Processing Error: This usually happens if there is no satellite coverage for the selected dates/location. Try an older date range.",
            "error",
          );
        } else {
          showNotification(error, "error");
        }
      } else {
        showNotification("Analysis triggered successfully", "success");
        // Refresh the runs list to show the new analysis
        await fetchRuns();
      }
    } catch (err) {
      const msg = err?.message || "";
      if (msg.includes("500") || msg.includes("Internal Server Error")) {
        showNotification(
          "The analysis pipeline failed. Please ensure your dates are at least 4 days in the past.",
          "error",
        );
      } else {
        showNotification(msg || "Analysis failed", "error");
      }
    } finally {
      setAnalyzeLoading(false);
    }
  };

  return (
    <div
      className="min-h-screen pt-14 flex flex-col"
      style={{ background: "#060504" }}
    >
      <div className="flex-1 flex flex-col max-w-[1700px] mx-auto w-full px-4 sm:px-8 py-6 sm:py-8 gap-6">
        {/* ── Page Header ───────────────────────────────────────── */}
        <div
          className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 pb-4"
          style={{ borderBottom: "1px solid rgba(242,209,109,0.15)" }}
        >
          <div>
            <span
              className="tracking-[0.35em] uppercase mb-2 block"
              style={{
                fontSize: "0.6rem",
                color: "#f2d16d",
                fontFamily: "monospace",
              }}
            >
              Intelligence Archive
            </span>
            <h1
              className="font-display font-light uppercase tracking-[0.2em]"
              style={{ fontSize: "1.4rem", color: "#ece8df" }}
            >
              Flood Insights
            </h1>
          </div>
          <DataSourceBadge />
        </div>

        {/* ── Two-Column Layout ──────────────────────────────── */}
        <div className="flex-1 grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* LEFT COLUMN: form + runs list */}
          <div
            className="lg:col-span-1 flex flex-col gap-0"
            style={{ border: "1px solid rgba(242,209,109,0.15)" }}
          >
            {/* Analyze Form */}
            <AnalyzeForm
              onSubmit={handleAnalyzeSubmit}
              isLoading={analyzeLoading}
            />

            {/* Column header */}
            <div
              className="px-4 py-3 border-b flex items-center justify-between"
              style={{
                borderColor: "rgba(242,209,109,0.15)",
                background: "rgba(242,209,109,0.03)",
              }}
            >
              <span
                className="font-mono text-[9px] uppercase tracking-[0.3em]"
                style={{ color: "#f2d16d" }}
              >
                Historical Runs
              </span>
              <span
                className="font-mono text-[9px] text-right"
                style={{ color: "rgba(236,232,223,0.3)" }}
              >
                {runsLoading ? "LOADING..." : `${runs.length} RECORDS`}
              </span>
            </div>

            {/* Run rows */}
            <div className="flex-1 overflow-y-auto">
              {runsError && <ErrorState message={runsError} />}
              {!runsLoading && !runsError && runs.length === 0 && (
                <div
                  className="px-4 py-8 text-center font-mono text-[10px]"
                  style={{ color: "rgba(236,232,223,0.3)" }}
                >
                  — No runs found —
                </div>
              )}
              <AnimatePresence>
                {runs.map((run, i) => (
                  <RunRow
                    key={run.run_id}
                    run={run}
                    index={i}
                    isSelected={selectedRunId === run.run_id}
                    onClick={() => selectRun(run.run_id)}
                  />
                ))}
              </AnimatePresence>
            </div>
          </div>

          {/* RIGHT PANEL: run detail */}
          <div className="lg:col-span-2 overflow-y-auto lg:max-h-[calc(100vh-10rem)] pr-1">
            <AnimatePresence mode="wait">
              {analyzeLoading && <AnalysisThinkingPanel key="thinking" />}
              {!analyzeLoading && !selectedRunId && !detailLoading && (
                <EmptyState key="empty" />
              )}
              {!analyzeLoading && detailLoading && (
                <motion.div
                  key="loading"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                >
                  <LoadingSkeleton />
                </motion.div>
              )}
              {!analyzeLoading && detailError && !detailLoading && (
                <ErrorState key="error" message={detailError} />
              )}
              {!analyzeLoading && selectedRun && !detailLoading && (
                <motion.div
                  key={selectedRun.run_id}
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -8 }}
                  transition={{ duration: 0.25 }}
                  className="space-y-4"
                >
                  {/* Export Button */}
                  <div className="flex justify-end">
                    <button
                      onClick={() => generateInsightsReport(selectedRun)}
                      className="text-[9px] font-mono uppercase tracking-widest px-3 py-1.5 border rounded transition-colors hover:bg-[rgba(242,209,109,0.1)]"
                      style={{
                        borderColor: "rgba(242,209,109,0.4)",
                        color: "#f2d16d",
                      }}
                    >
                      Export PDF
                    </button>
                  </div>

                  {/* Row 1: Key metrics grid */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <StatCard
                      label="Flood Area"
                      value={data.flood_area_km2}
                      decimals={0}
                      unit=" km²"
                      color="#d4900a"
                    />
                    <StatCard
                      label="Flood %"
                      value={data.flood_percentage}
                      decimals={1}
                      unit="%"
                      color="#f2d16d"
                    />
                    <StatCard
                      label="Severity"
                      customContent={
                        <div
                          className="px-3 py-1.5 rounded-full inline-flex items-center gap-1.5 border font-mono text-sm font-medium"
                          style={{
                            background: "rgba(242,209,109,0.1)",
                            borderColor: "rgba(242,209,109,0.3)",
                            color: "#f2d16d",
                          }}
                        >
                          <span
                            className="w-1.5 h-1.5 rounded-full"
                            style={{ background: "#f2d16d" }}
                          />
                          {data.severity}
                        </div>
                      }
                    />
                    <StatCard
                      label="Risk"
                      customContent={
                        <RiskBadge
                          risk={data.risk_label}
                          size="md"
                          showDot={true}
                        />
                      }
                    />
                  </div>

                  {/* Row 2: Details */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div
                      className="p-4 rounded border"
                      style={{
                        borderColor: "rgba(242,209,109,0.15)",
                        background: "rgba(242,209,109,0.03)",
                      }}
                    >
                      <div
                        className="text-[11px] font-mono uppercase tracking-widest"
                        style={{ color: "rgba(236,232,223,0.4)" }}
                      >
                        Total Patches
                      </div>
                      <div
                        className="text-2xl font-mono font-bold mt-2"
                        style={{ color: "#f2d16d" }}
                      >
                        {data.total_patches?.toLocaleString() ?? "N/A"}
                      </div>
                    </div>
                    <div
                      className="p-4 rounded border"
                      style={{
                        borderColor: "rgba(242,209,109,0.15)",
                        background: "rgba(242,209,109,0.03)",
                      }}
                    >
                      <div
                        className="text-[11px] font-mono uppercase tracking-widest"
                        style={{ color: "rgba(236,232,223,0.4)" }}
                      >
                        Largest Patch
                      </div>
                      <div
                        className="text-2xl font-mono font-bold mt-2"
                        style={{ color: "#4ab0d8" }}
                      >
                        {data.largest_patch_km2?.toLocaleString() ?? "N/A"} km²
                      </div>
                    </div>
                  </div>

                  {/* Location Trend Chart — if 3+ runs for this location */}
                  {(() => {
                    const locationKey = selectedRun?.location_name
                      ?.split(",")[0]
                      ?.trim();
                    const locationRuns = runsByLocation[locationKey] ?? [];
                    return locationRuns.length >= 3 ?
                        <LocationTrendChart locationRuns={locationRuns} />
                      : null;
                  })()}

                  {/* Change detection image */}
                  <ChangeDetectionImage
                    src={selectedRun.panel_png_path}
                    location={selectedRun.location_name}
                    bbox={selectedRun.aoi_bbox}
                    resolution={selectedRun.resolution_m}
                  />

                  {/* AI Insight */}
                  <AIInsightPanel selectedRun={selectedRun} />
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  );
}
