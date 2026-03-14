const COLORS = {
  CRITICAL: "bg-red-600 text-white",
  HIGH:     "bg-orange-500 text-white",
  MEDIUM:   "bg-yellow-500 text-black",
  LOW:      "bg-green-600 text-white",
  UNKNOWN:  "bg-gray-600 text-white",
}

export default function SeverityBadge({ level }) {
  return (
    <span className={`text-xs font-bold px-2 py-0.5 rounded ${COLORS[level] ?? COLORS.UNKNOWN}`}>
      {level}
    </span>
  )
}