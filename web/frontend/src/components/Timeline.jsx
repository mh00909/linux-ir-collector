import { useEffect, useState } from "react"

export default function Timeline({ reportId }) {
  const [lines, setLines] = useState([])

  useEffect(() => {
    fetch(`http://localhost:8000/api/reports/${reportId}/timeline`)
      .then(r => r.json())
      .then(d => setLines(d.lines ?? []))
      .catch(() => setLines(["Timeline unavailable."]))
  }, [reportId])

  return (
    <div className="font-mono text-xs bg-gray-900 rounded p-4 overflow-x-auto max-h-[60vh] overflow-y-auto">
      {lines.map((line, i) => (
        <div
          key={i}
          className={`py-0.5 ${line.includes("Failed") ? "text-red-400" : "text-gray-300"}`}
        >
          {line}
        </div>
      ))}
    </div>
  )
}