import { useEffect, useState } from "react"
import SeverityBadge from "./SeverityBadge"

export default function ReportList({ onSelect, selected }) {
  const [reports, setReports] = useState([])

  useEffect(() => {
    fetch("http://localhost:8000/api/reports")
      .then(r => r.json())
      .then(setReports)
  }, [])

  return (
    <ul className="space-y-2">
      {reports.map(r => (
        <li
          key={r.id}
          onClick={() => onSelect(r.id)}
          className={`p-3 rounded cursor-pointer border transition
            ${selected === r.id
              ? "border-green-500 bg-gray-800"
              : "border-gray-700 hover:border-gray-500"}`}
        >
          <div className="flex justify-between items-center">
            <span className="text-xs text-gray-400 font-mono">{r.generated}</span>
            <SeverityBadge level={r.severity} />
          </div>
          <p className="text-xs text-gray-500 mt-1 truncate">{r.id}</p>
        </li>
      ))}
    </ul>
  )
}