import { useEffect, useState } from "react"
import SeverityBadge from "./SeverityBadge"
import Timeline from "./Timeline"

export default function ReportDetail({ reportId }) {
  const [report, setReport] = useState(null)
  const [tab, setTab] = useState("overview")

  useEffect(() => {
    setReport(null)
    fetch(`http://localhost:8000/api/reports/${reportId}`)
      .then(r => r.json())
      .then(setReport)
  }, [reportId])

  if (!report) return <p className="text-gray-500">Ładowanie...</p>

  const results = report.results ?? {}
  const severity = results.severity ?? {}
  const logs = results.logs?.findings ?? {}
  const persistence = results.persistence?.findings ?? {}

  return (
    <div>
      <div className="flex items-center gap-3 mb-6">
        <h2 className="text-xl font-bold font-mono">{reportId}</h2>
        <SeverityBadge level={severity.level} />
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6 border-b border-gray-800">
        {["overview", "ssh", "persistence", "timeline"].map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm transition
              ${tab === t
                ? "border-b-2 border-green-400 text-green-400"
                : "text-gray-400 hover:text-gray-200"}`}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === "overview" && (
        <div className="space-y-3">
          <p className="text-sm text-gray-400">Generated: {report.generated}</p>
          <h3 className="font-semibold text-gray-300">Reasons:</h3>
          <ul className="list-disc list-inside text-sm space-y-1">
            {(severity.reasons ?? []).map((r, i) => (
              <li key={i} className="text-gray-300">{r}</li>
            ))}
          </ul>
        </div>
      )}

      {tab === "ssh" && (
        <div className="space-y-4">
          <div className="grid grid-cols-3 gap-4">
            {[
              ["Log source", logs.log_source ?? "—"],
              ["Failed attempts", logs.failed_password_count ?? 0],
              ["Unique IPs", logs.unique_source_ips ?? 0],
            ].map(([label, value]) => (
              <div key={label} className="bg-gray-800 rounded p-4">
                <p className="text-xs text-gray-400">{label}</p>
                <p className="text-2xl font-bold text-green-400">{value}</p>
              </div>
            ))}
          </div>
          <h3 className="font-semibold text-gray-300 mt-4">Top source IPs:</h3>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-400 border-b border-gray-700">
                <th className="text-left py-2">IP</th>
                <th className="text-right py-2">Count</th>
              </tr>
            </thead>
            <tbody>
              {(logs.top_source_ips ?? []).map(({ ip, count }) => (
                <tr key={ip} className="border-b border-gray-800">
                  <td className="py-2 font-mono">{ip}</td>
                  <td className="py-2 text-right text-orange-400">{count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === "persistence" && (
        <div className="space-y-4 text-sm">
          <p>Enabled services: <strong>{persistence.enabled_services_count ?? 0}</strong></p>
          <p>Timers: <strong>{persistence.timers_listed_count ?? 0}</strong></p>
          <h3 className="font-semibold text-gray-300 mt-4">Suspicious cron entries:</h3>
          {(persistence.suspicious_cron_entries ?? []).length === 0
            ? <p className="text-gray-500">Brak.</p>
            : (persistence.suspicious_cron_entries ?? []).map((e, i) => (
                <pre key={i} className="bg-gray-800 p-2 rounded text-red-400 text-xs overflow-x-auto">{e}</pre>
              ))
          }
        </div>
      )}

      {tab === "timeline" && <Timeline reportId={reportId} />}
    </div>
  )
}