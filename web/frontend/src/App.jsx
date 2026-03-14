import { useState } from "react"
import ReportList from "./components/ReportList"
import ReportDetail from "./components/ReportDetail"

export default function App() {
  const [selected, setSelected] = useState(null)

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 flex">
      <aside className="w-80 border-r border-gray-800 p-4">
        <h1 className="text-lg font-bold text-green-400 mb-4">
          🛡 IR Collector
        </h1>
        <ReportList onSelect={setSelected} selected={selected} />
      </aside>
      <main className="flex-1 p-6">
        {selected
          ? <ReportDetail reportId={selected} />
          : <p className="text-gray-500">Wybierz raport z listy.</p>
        }
      </main>
    </div>
  )
}