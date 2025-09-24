import React, { useEffect, useMemo, useState, useRef } from "react";
import axios from "axios";
import { Line, Doughnut } from "react-chartjs-2";
import {
  Chart as ChartJS,
  LineElement,
  ArcElement,
  CategoryScale,
  LinearScale,
  PointElement,
  Tooltip,
  Legend,
} from "chart.js";
import { motion, AnimatePresence } from "framer-motion";

ChartJS.register( LineElement, ArcElement, CategoryScale, LinearScale, PointElement, Tooltip, Legend );

const API_BASE = "http://127.0.0.1:8000";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const chip = (text, color) => (<span className={`px-2 py-0.5 rounded text-xs font-semibold ${color}`}>{text}</span>);

const AuthPage = ({ onLoginSuccess }) => {
    const [isLogin, setIsLogin] = useState(true);
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault(); setError(''); setLoading(true);
        try {
            if (isLogin) {
                const form = new FormData();
                form.append("username", username); form.append("password", password);
                const res = await axios.post(`${API_BASE}/login`, form);
                if (res.data.access_token) onLoginSuccess(res.data.access_token, username);
            } else {
                await axios.post(`${API_BASE}/users/register`, { username, password });
                const form = new FormData();
                form.append("username", username); form.append("password", password);
                const loginRes = await axios.post(`${API_BASE}/login`, form);
                if (loginRes.data.access_token) onLoginSuccess(loginRes.data.access_token, username);
            }
        } catch (err) { setError(err.response?.data?.detail || `An error occurred.`);
        } finally { setLoading(false); }
    };

    return (
        <div className="min-h-screen bg-white text-black flex items-center justify-center p-4">
            <div className="w-full max-w-md p-8 space-y-8 bg-gray-100 rounded-2xl shadow-lg border border-slate-300">
                <div className="text-center"><h2 className="text-3xl font-extrabold text-emerald-600">Synapse Sentinel</h2><p className="mt-2 text-slate-600">{isLogin ? 'Welcome back! Please log in.' : 'Create a new account.'}</p></div>
                <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
                    <div><input id="username" name="username" type="text" required className="appearance-none rounded-t-md relative block w-full px-3 py-2 border border-slate-300 bg-white placeholder-slate-500 text-black focus:outline-none focus:ring-emerald-500 focus:border-emerald-500 sm:text-sm" placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} /></div>
                    <div><input id="password" name="password" type="password" required className="appearance-none rounded-b-md relative block w-full px-3 py-2 border border-slate-300 bg-white placeholder-slate-500 text-black focus:outline-none focus:ring-emerald-500 focus:border-emerald-500 sm:text-sm" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} /></div>
                    {error && <p className="text-sm text-red-500 text-center">{error}</p>}
                    <div><button type="submit" disabled={loading} className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-emerald-600 hover:bg-emerald-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-100 focus:ring-emerald-500 disabled:bg-slate-400">{loading ? 'Processing...' : (isLogin ? 'Log In' : 'Sign Up')}</button></div>
                </form>
                <div className="text-sm text-center"><button onClick={() => { setIsLogin(!isLogin); setError(''); }} className="font-medium text-emerald-600 hover:text-emerald-500">{isLogin ? 'Need an account? Sign Up' : 'Already have an account? Log In'}</button></div>
            </div>
        </div>
    );
};

const Dashboard = ({ token, username, onLogout }) => {
    const [connected, setConnected] = useState(false);
    const [alerts, setAlerts] = useState([]);
    const [logs, setLogs] = useState([]);
    const logsIdRef = useRef(new Set());
    const [page, setPage] = useState(1);
    const [pages, setPages] = useState(1);
    const [limit, setLimit] = useState(25);
    const [filterType, setFilterType] = useState("All");
    const [filterSeverity, setFilterSeverity] = useState("All");
    const [packetRate, setPacketRate] = useState(0);
    const [rateHistory, setRateHistory] = useState([]);
    const [sidebarOpen, setSidebarOpen] = useState(false);
    const [downloading, setDownloading] = useState(false);
    const [blockStatus, setBlockStatus] = useState({});

    useEffect(() => { if (token) { axios.defaults.headers.common["Authorization"] = `Bearer ${token}`; } }, [token]);

    useEffect(() => {
        let stop = false;
        const tick = async () => {
          while (!stop) {
            try {
              const [logsRes, prRes] = await Promise.all([ axios.get(`${API_BASE}/logs`, { params: { page, limit, type: filterType, severity: filterSeverity } }), axios.get(`${API_BASE}/packet_rate`), ]);
              setConnected(true);
              const newLogsData = logsRes.data || {};
              setLogs(newLogsData.items || []);
              setPages(newLogsData.pages || 1);
              const newAnomalies = (newLogsData.items || []).filter(log => log.severity !== "Normal" && !logsIdRef.current.has(log.index));
              if (newAnomalies.length > 0) {
                  newAnomalies.forEach(log => logsIdRef.current.add(log.index));
                  const newAlerts = newAnomalies.map(log => ({ t: new Date().toLocaleTimeString(), src: log.src_ip, size: log.size, sev: log.severity, atk: log.attack_type, by: log.detected_by, conf: log.ml_confidence, score: log.abuse_score }));
                  setAlerts(prev => [...newAlerts, ...prev].slice(0, 20));
              }
              setPacketRate(prRes.data?.rate ?? 0);
              setRateHistory(prRes.data?.history ?? []);
            } catch (err) { setConnected(false); }
            await sleep(2500);
          }
        };
        tick();
        return () => { stop = true; };
    }, [page, limit, filterType, filterSeverity]);

    const handleBlockIp = async (ip) => {
        if (window.confirm(`Are you sure you want to block the IP address: ${ip}?`)) {
            setBlockStatus({ ip, loading: true, message: '' });
            try {
                const res = await axios.post(`${API_BASE}/block/${ip}`);
                setBlockStatus({ ip, loading: false, message: res.data.message });
            } catch (err) { setBlockStatus({ ip, loading: false, message: 'Error: Could not block IP.' }); }
        }
    };
    
    const downloadPDF = async () => {
        setDownloading(true);
        try {
          const res = await axios.get(`${API_BASE}/export`, { responseType: "blob" });
          const blob = new Blob([res.data], { type: "application/pdf" });
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement("a"); a.href = url; a.download = "logs.pdf";
          document.body.appendChild(a); a.click(); a.remove(); window.URL.revokeObjectURL(url);
        } catch (err) { alert("Failed to download PDF report."); }
        setDownloading(false);
    };
    
    const handleReset = async () => {
        if (window.confirm("Are you sure you want to delete all logs? This cannot be undone.")) {
            try {
              await axios.post(`${API_BASE}/reset`);
              setAlerts([]); setLogs([]); setPage(1);
            } catch (err) { alert("Failed to reset logs."); }
        }
    };

    const totalPackets = useMemo(() => logs.length + (pages > 1 ? (page-1) * limit : 0), [logs, pages, page, limit]); // More accurate count
    const totalAnomalies = useMemo(() => logs.filter(r => r.severity !== "Normal").length, [logs]);
    const severityCounts = useMemo(() => logs.reduce((acc, r) => { (acc[r.severity] = (acc[r.severity] || 0) + 1); return acc; }, {}), [logs]);
    const trafficData = { labels: rateHistory.map(p => new Date(p.ts * 1000).toLocaleTimeString()), datasets: [{ label: "Packets Per Second", data: rateHistory.map(p => p.count), borderColor: "#22c55e", backgroundColor: "rgba(34,197,94,0.2)", tension: 0.35, pointRadius: 2, fill: true, }]};
    const donutData = { labels: ["High", "Medium", "Low", "Normal"], datasets: [{ data: [severityCounts.High||0, severityCounts.Medium||0, severityCounts.Low||0, severityCounts.Normal||0], backgroundColor: ["#ef4444", "#f59e0b", "#84cc16", "#64748b"], borderColor: "#0b0f14", borderWidth: 2, }]};
    const chartCommon = { plugins: { legend: { labels: { color: "#0b0f14" } } }, scales: { x: { ticks: { color: "#333" }, grid: { color: "rgba(148,163,184,0.18)" } }, y: { ticks: { color: "#333", beginAtZero: true }, grid: { color: "rgba(148,163,184,0.18)" } } } };
    const sevChip = (s) => { if (s === "High") return chip("High", "bg-red-600 text-white"); if (s === "Medium") return chip("Medium", "bg-yellow-500 text-black"); if (s === "Low") return chip("Low", "bg-lime-500 text-black"); return chip("Normal", "bg-slate-600 text-white"); };
    const byChip = (b) => { if (b === "Threat Intel") return chip("Threat Intel", "bg-red-800 text-white"); return b === "ML" ? chip("ML", "bg-purple-600 text-white") : b === "Rule" ? chip("Rule", "bg-sky-600 text-white") : chip("None", "bg-slate-600 text-white"); };
    
    return (
        <div className="min-h-screen bg-white text-black">
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-300 bg-white shadow"><div className="flex items-center gap-3"><button onClick={() => setSidebarOpen((s) => !s)} className="w-10 h-10 grid place-items-center rounded hover:bg-slate-200" title="Menu"><div className="w-5 border-t-2 border-black" /><div className="w-5 border-t-2 border-black mt-1" /><div className="w-5 border-t-2 border-black mt-1" /></button><h1 className="text-2xl md:text-3xl font-extrabold tracking-wide">Synapse Sentinel</h1></div><div className="flex items-center gap-3"><span className={`px-3 py-1 rounded-full text-sm font-semibold ${connected ? "bg-emerald-500 text-white" : "bg-red-600 text-white"}`}>{connected ? "Connected" : "Disconnected"}</span></div></div>
          <div className="relative flex">
            <AnimatePresence><motion.aside key={String(sidebarOpen)} className="h-[calc(100vh-57px)] sticky top-[57px] bg-gray-50 border-r border-slate-300 z-20" initial={{ width: 0 }} animate={{ width: sidebarOpen ? 288 : 0 }} exit={{ width: 0 }} transition={{ type: "spring", stiffness: 250, damping: 28 }} style={{ overflow: "hidden" }}><div className="h-full w-72 px-4 py-4"><div className="text-lg font-bold mb-3 text-emerald-600">⚡ Menu</div><button onClick={downloadPDF} className="w-full text-left px-3 py-2 rounded bg-gray-200 hover:bg-violet-200 border border-slate-300 transition text-black">⬇️ Export PDF</button><button onClick={handleReset} className="w-full mt-2 text-left px-3 py-2 rounded bg-gray-200 hover:bg-amber-200 border border-slate-300 transition text-black">♻️ Reset Logs</button><div className="bg-gray-200 rounded-lg p-3 border border-slate-300 mt-3"><div className="text-sm opacity-90 mb-2">Filters</div><div className="grid grid-cols-2 gap-2"><select value={filterType} onChange={(e) => { setPage(1); setFilterType(e.target.value); }} className="bg-gray-300 rounded px-2 py-1">{["All", "Possible DDoS", "Suspicious Host", "AI Flagged Anomaly", "High-Risk IP", "Normal", "Large Packet"].map((t) => (<option key={t}>{t}</option>))}</select><select value={filterSeverity} onChange={(e) => { setPage(1); setFilterSeverity(e.target.value); }} className="bg-gray-300 rounded px-2 py-1">{["All", "High", "Medium", "Low", "Normal"].map((t) => (<option key={t}>{t}</option>))}</select></div></div><div className="text-sm opacity-80 mt-3">User: <span className="font-semibold">{username}</span></div><button onClick={onLogout} className="w-full mt-2 text-left px-3 py-2 rounded bg-gray-200 hover:bg-red-200 border border-slate-300 transition">🚪 Logout</button>{downloading && (<div className="mt-4 text-xs opacity-80">Preparing PDF…</div>)}</div></motion.aside></AnimatePresence>
            <motion.main className="flex-1 p-4 md:p-6 bg-white text-black" animate={{ paddingLeft: sidebarOpen ? 16 : 24 }} transition={{ type: "spring", stiffness: 250, damping: 28 }}>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                    <div className="bg-gray-100 rounded-xl p-4 border border-slate-300"><div className="text-sm text-gray-600">Total Packets</div><div className="text-2xl font-bold">{totalPackets}</div></div>
                    <div className="bg-gray-100 rounded-xl p-4 border border-slate-300"><div className="text-sm text-gray-600">Anomalies</div><div className="text-2xl font-bold text-rose-600">{totalAnomalies}</div></div>
                    <div className="bg-gray-100 rounded-xl p-4 border border-slate-300"><div className="text-sm text-gray-600">Packet Rate (p/s)</div><div className="text-2xl font-bold">{packetRate.toFixed(2)}</div></div>
                    <div className="bg-gray-100 rounded-xl p-4 border border-slate-300"><div className="text-sm text-gray-600">Status</div><div className="text-2xl font-bold">{connected ? 'Online' : 'Offline'}</div></div>
                </div>
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
                    <div className="lg:col-span-2 bg-gray-100 rounded-xl p-4 border border-slate-300"><div className="font-semibold text-black mb-2">Network Traffic Rate</div><Line data={trafficData} options={chartCommon} /></div>
                    <div className="bg-gray-100 rounded-xl p-4 border border-slate-300"><div className="font-semibold text-black mb-2">Anomalies Detected</div><Doughnut data={donutData} options={{ plugins: { legend: { labels: { color: "#0b0f14" } } } }} /></div>
                </div>
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                    <div className="bg-gray-100 rounded-xl p-4 border border-slate-300">
                        <div className="font-semibold text-black mb-2">Real-time Alerts</div>
                        <div className="space-y-2 max-h-[400px] overflow-auto pr-1">
                            {alerts.length === 0 && <div className="text-sm text-gray-600">No new anomalies</div>}
                            {alerts.map((a, i) => (<div key={i} className="p-2 rounded bg-gray-200 border border-slate-300"><div className="text-xs text-gray-600">{a.t}</div><div className="text-sm">Packet from <span className="font-semibold">{a.src}</span></div><div className="mt-1 flex flex-wrap items-center gap-2">{sevChip(a.sev)}{chip(a.atk, "bg-amber-600 text-black")}{byChip(a.by)}{a.score > 0 && <span className="font-bold text-red-500 text-xs">(Abuse: {a.score}%)</span>}</div></div>))}
                        </div>
                    </div>
                    <div className="lg:col-span-2 bg-gray-100 rounded-xl p-3 border border-slate-300">
                        <div className="flex items-center justify-between mb-2"><div className="font-semibold">Secure Logs</div><div className="flex items-center gap-2 text-sm"><span className="text-gray-600">Rows:</span><select value={limit} onChange={(e) => { setPage(1); setLimit(+e.target.value); }} className="bg-gray-300 rounded px-2 py-1">{[10, 25, 50, 100].map((n) => (<option key={n} value={n}>{n}</option>))}</select></div></div>
                        <div className="overflow-auto"><table className="min-w-full text-sm"><thead className="sticky top-0 bg-gray-200/80 backdrop-blur z-10"><tr>
                            {["Index", "Timestamp", "Src IP", "Dst IP", "Size", "Abuse Score", "Severity", "Attack Type", "Detected By", "Conf", "Hostname", "Hash", "Actions"].map((h) => (<th key={h} className="px-2 py-2 border-b border-slate-300 whitespace-nowrap">{h}</th>))}
                        </tr></thead><tbody>
                            {logs.map((r) => (<tr key={r.index} className="border-b border-slate-300 hover:bg-gray-200"><td className="px-2 py-2">{r.index}</td><td className="px-2 py-2 whitespace-nowrap">{r.timestamp}</td><td className="px-2 py-2">{r.src_ip}</td><td className="px-2 py-2">{r.dst_ip}</td><td className="px-2 py-2">{r.size}</td><td className={`px-2 py-2 font-bold ${r.abuse_score > 75 ? 'text-red-600' : r.abuse_score > 25 ? 'text-yellow-600' : ''}`}>{r.abuse_score !== null ? `${r.abuse_score}%` : '-'}</td><td className="px-2 py-2">{sevChip(r.severity)}</td><td className="px-2 py-2"><span className="truncate inline-block max-w-[160px]" title={r.attack_type}>{r.attack_type}</span></td><td className="px-2 py-2">{byChip(r.detected_by)}</td><td className="px-2 py-2">{r.detected_by === "ML" ? `${Math.round(r.ml_confidence * 100)}%` : "-"}</td><td className="px-2 py-2 truncate" title={r.hostname}>{r.hostname}</td><td className="px-2 py-2 truncate max-w-[100px]" title={r.hash}>{r.hash}</td><td className="px-2 py-2">{r.severity === 'High' && (<button onClick={() => handleBlockIp(r.src_ip)} disabled={blockStatus.loading && blockStatus.ip === r.src_ip} className="px-3 py-1 text-xs font-semibold text-white bg-red-600 rounded hover:bg-red-700 disabled:bg-gray-400">Block</button>)}</td></tr>))}
                            {logs.length === 0 && (<tr><td className="px-2 py-8 text-center text-gray-600" colSpan={13}>No data</td></tr>)}
                        </tbody></table></div>
                        {blockStatus.message && <div className="mt-2 text-sm text-center text-blue-600">{blockStatus.message}</div>}
                        <div className="flex items-center justify-end gap-2 mt-3"><button disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))} className={`px-3 py-1 rounded ${page <= 1 ? "bg-gray-300 opacity-50" : "bg-gray-300 hover:bg-gray-400"}`}>Prev</button><span className="text-sm text-gray-600">Page {page} / {pages}</span><button disabled={page >= pages} onClick={() => setPage((p) => Math.min(pages, p + 1))} className={`px-3 py-1 rounded ${page >= pages ? "bg-gray-300 opacity-50" : "bg-gray-300 hover:bg-gray-400"}`}>Next</button></div>
                    </div>
                </div>
            </motion.main>
          </div>
        </div>
    );
};

function App() {
  const [token, setToken] = useState(localStorage.getItem("token"));
  const [username, setUsername] = useState(localStorage.getItem("username"));

  const handleLoginSuccess = (newToken, newUsername) => {
    localStorage.setItem("token", newToken);
    localStorage.setItem("username", newUsername);
    setToken(newToken);
    setUsername(newUsername);
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("username");
    delete axios.defaults.headers.common["Authorization"];
    setToken(null);
    setUsername(null);
  };

  return (
    <>
      {token ? (
        <Dashboard token={token} username={username} onLogout={handleLogout} />
      ) : (
        <AuthPage onLoginSuccess={handleLoginSuccess} />
      )}
    </>
  );
}

export default App;