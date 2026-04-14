"use client";

import { useState, useEffect } from "react";
import { useScans, useGenerateReport } from "@/lib/hooks";
import { EmptyState, Skeleton } from "@/components/ui";
import { FileText, Download, Loader2, CheckCircle, AlertTriangle, CalendarDays, ExternalLink, Link, Clock, Plus, Folder, MessageSquare, BarChart2, Trash2, RefreshCw } from "lucide-react";
import api from "@/lib/api";

interface GeneratedReport {
  scanId: string;
  domain: string;
  generatedAt: string;
  reportType: string;
}

export default function ReportsPage() {
  const { data: scans, isLoading: scansLoading } = useScans();
  const generateReport = useGenerateReport();
  const [isScheduled, setIsScheduled] = useState(false);
  const [currentTime, setCurrentTime] = useState<Date | null>(null);

  useEffect(() => {
    setCurrentTime(new Date());
    const interval = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(interval);
  }, []);

  // Common State
  const [reportType, setReportType] = useState("executive");
  const [selectedScanId, setSelectedScanId] = useState("");
  
  // On-Demand State
  const [sendViaEmail, setSendViaEmail] = useState(true);
  const [emailAddress, setEmailAddress] = useState("");
  const [saveToLocation, setSaveToLocation] = useState(true);
  const [locationPath, setLocationPath] = useState("/Reports/OnDemand/");
  const [downloadLink, setDownloadLink] = useState(false);
  const [slackNotif, setSlackNotif] = useState(false);
  const [includeCharts, setIncludeCharts] = useState(true);
  const [fileFormat, setFileFormat] = useState("pdf");
  const [passwordProtect, setPasswordProtect] = useState(false);

  // Schedule State
  const [frequency, setFrequency] = useState("Weekly");
  const [targetAssets, setTargetAssets] = useState("All Assets");
  const [sections, setSections] = useState({
    discovery: true, inventory: true, cbom: true, posture: true, rating: true,
  });
  const [scheduleDate, setScheduleDate] = useState("2026-04-25");
  const [scheduleTime, setScheduleTime] = useState("09:00");
  const [timeZone, setTimeZone] = useState("Asia/Kolkata");
  
  const [emailChecked, setEmailChecked] = useState(true);
  const [schedEmail, setSchedEmail] = useState("executives@org.com");
  const [schedSaveChecked, setSchedSaveChecked] = useState(true);
  const [schedLocation, setSchedLocation] = useState("/Reports/Quarterly/");
  const [schedDownload, setSchedDownload] = useState(false);

  // Status State
  const [generating, setGenerating] = useState(false);
  const [generatedReports, setGeneratedReports] = useState<GeneratedReport[]>([]);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Schedules List State
  const [schedules, setSchedules] = useState<any[]>([]);
  const [loadingSchedules, setLoadingSchedules] = useState(false);

  const fetchSchedules = async () => {
    setLoadingSchedules(true);
    try {
      const { data } = await api.get("/reports/schedules");
      setSchedules(data);
    } catch {}
    setLoadingSchedules(false);
  };

  const handleDeleteSchedule = async (id: string) => {
    try {
      await api.delete(`/reports/schedules/${id}`);
      setSchedules(prev => prev.filter(s => s.id !== id));
    } catch {
      setErrorMsg("Failed to delete schedule.");
    }
  };

  useEffect(() => {
    if (isScheduled) fetchSchedules();
  }, [isScheduled]);

  useEffect(() => {
    if (typeof window !== "undefined") {
      const saved = localStorage.getItem("qushield_reports");
      if (saved) {
        try {
          const parsed = JSON.parse(saved) as GeneratedReport[];
          setGeneratedReports(parsed.map(item => ({...item, reportType: item.reportType || "executive"})));
        } catch {}
      }
    }
  }, []);

  const completedScans = (scans || []).filter((s) => s.status === "completed");
  
  // Select latest scan by default if user hasn't selected
  useEffect(() => {
    if (completedScans.length > 0 && !selectedScanId) {
      setSelectedScanId(completedScans[0].scan_id);
    }
  }, [completedScans, selectedScanId]);

  const handleGenerate = async () => {
    if (!selectedScanId) {
      setErrorMsg("Please select a scan to generate the report from.");
      return;
    }
    setGenerating(true);
    setSuccessMsg(null);
    setErrorMsg(null);
    try {
      let runPassword = null;
      if (passwordProtect) {
        runPassword = Math.random().toString(36).slice(-8);
      }
      
      const blob = await generateReport.mutateAsync({ scanId: selectedScanId, reportType, format: fileFormat.toLowerCase(), password: runPassword ?? undefined });
      
      const mimeTypes: Record<string, string> = {
        pdf: "application/pdf",
        csv: "text/csv",
        json: "application/json"
      };
      
      const url = URL.createObjectURL(new Blob([blob], { type: mimeTypes[fileFormat.toLowerCase()] || "application/pdf" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `qushield_${reportType}_${selectedScanId.slice(0, 8)}.${fileFormat.toLowerCase()}`;
      a.click();
      URL.revokeObjectURL(url);

      const scan = completedScans.find((s) => s.scan_id === selectedScanId);
      const newReport: GeneratedReport = {
        scanId: selectedScanId,
        domain: scan?.targets.join(", ") || selectedScanId.slice(0, 8),
        generatedAt: new Date().toISOString(),
        reportType,
      };
      const updated = [newReport, ...generatedReports].slice(0, 20);
      setGeneratedReports(updated);
      localStorage.setItem("qushield_reports", JSON.stringify(updated));
      
      if (runPassword) {
        alert(`Report downloaded and protected with password: ${runPassword}\n\nPlease save this password securely.`);
      }
      
      setSuccessMsg("Report generated and downloaded successfully!");
    } catch (err) {
      setErrorMsg("Failed to generate report. Please try again.");
    } finally {
      setGenerating(false);
    }
  };

  const handleSchedule = async () => {
    setGenerating(true);
    setSuccessMsg(null);
    setErrorMsg(null);
    try {
      await api.post("/reports/schedule", {
        report_type: reportType,
        frequency,
        target_assets: targetAssets,
        sections: Object.keys(sections).filter(k => (sections as any)[k]),
        schedule_date: `${scheduleDate}T${scheduleTime}:00`,
        schedule_time: scheduleTime,
        time_zone: timeZone,
        delivery_email: emailChecked ? schedEmail : null,
        delivery_location: schedSaveChecked ? schedLocation : null,
        download_link: schedDownload,
      });
      setSuccessMsg("Report scheduled successfully!");
      fetchSchedules();
    } catch (err) {
      setErrorMsg("Failed to schedule report. Please check your backend engine.");
    } finally {
      setGenerating(false);
    }
  };

  const reportOptions: { value: string; label: string; disabled?: boolean }[] = [
    { value: "executive", label: "Quantum Risk Executive Summary" },
    { value: "full_scan", label: "Full Infrastructure Scan" },
    { value: "rbi_submission", label: "RBI Crypto Governance" },
    { value: "cbom_audit", label: "CBOM Audit Package" },
    { value: "migration_progress", label: "PQC Migration Progress" },
  ];

  return (
    <div className="animate-fade-in flex justify-center py-10">
      
      <div className="glass-card-static w-full max-w-5xl rounded-2xl overflow-hidden" style={{ background: "var(--bg-card)" }}>
        {/* Header / Toggle area */}
        <div className="p-6 border-b flex justify-between items-center" style={{ borderColor: "var(--border-subtle)" }}>
          <div className="flex items-center gap-3">
            {isScheduled ? (
              <div className="p-2 rounded-lg bg-orange-500/20 text-orange-500">
                <CalendarDays size={24} />
              </div>
            ) : (
              <div className="p-2 rounded-lg bg-yellow-500/20 text-yellow-500">
                <BarChart2 size={24} />
              </div>
            )}
            <div>
              <h2 className="text-xl font-bold" style={{ color: "var(--text-primary)" }}>
                {isScheduled ? "Schedule Reporting" : "On-Demand Reporting"}
              </h2>
              <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                {isScheduled ? "Set up recurring automated scans and reports" : "Request reports as needed"}
              </p>
            </div>
          </div>
          
          <div className="flex items-center gap-3">
            <span className="text-sm font-semibold" style={{ color: "var(--text-secondary)" }}>
              Enable Schedule
            </span>
            <button
              onClick={() => setIsScheduled(!isScheduled)}
              className={`w-12 h-6 rounded-full p-1 transition-colors duration-200 ease-in-out ${isScheduled ? 'bg-orange-500' : 'bg-gray-600'}`}
            >
              <div
                className={`bg-white w-4 h-4 rounded-full shadow-md transform transition-transform duration-200 ease-in-out ${isScheduled ? 'translate-x-6' : 'translate-x-0'}`}
              />
            </button>
          </div>
        </div>

        <div className="p-8">
          {successMsg && (
            <div className="flex items-center gap-2 p-3 rounded-lg mb-6" style={{ background: "color-mix(in srgb, var(--risk-ready) 14%, transparent)", color: "var(--risk-ready)" }}>
              <CheckCircle size={16} /> <span className="text-sm">{successMsg}</span>
            </div>
          )}
          {errorMsg && (
            <div className="flex items-center gap-2 p-3 rounded-lg mb-6" style={{ background: "color-mix(in srgb, var(--risk-critical) 14%, transparent)", color: "var(--risk-critical)" }}>
              <AlertTriangle size={16} /> <span className="text-sm">{errorMsg}</span>
            </div>
          )}

          {!isScheduled ? (
            /* ON_DEMAND MODE */
            <div className="grid grid-cols-1 md:grid-cols-2 gap-12">
              <div className="space-y-6">
                <div>
                  <label className="block text-xs font-bold mb-2">Report Type</label>
                  <select
                    className="w-full p-3 rounded border text-sm"
                    style={{ background: "transparent", borderColor: "var(--accent-gold)", color: "var(--text-primary)", outline: "none" }}
                    value={reportType}
                    onChange={(e) => setReportType(e.target.value)}
                  >
                    {reportOptions.map(o => (
                      <option key={o.value} value={o.value} disabled={o.disabled} className="text-black">{o.label}</option>
                    ))}
                  </select>
                </div>
                
                <div>
                  <label className="block text-xs font-bold mb-2">Select Target Scan</label>
                  <select
                    className="w-full p-3 rounded border text-sm"
                    style={{ background: "transparent", borderColor: "var(--border-subtle)", color: "var(--text-primary)", outline: "none" }}
                    value={selectedScanId}
                    onChange={(e) => setSelectedScanId(e.target.value)}
                  >
                    <option value="" className="text-black">Select recent scan...</option>
                    {completedScans.map(s => (
                      <option key={s.scan_id} value={s.scan_id} className="text-black">
                        {s.targets.join(", ")} ({new Date(s.created_at).toLocaleDateString()})
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="bg-white/5 border rounded-xl p-5" style={{ borderColor: "var(--border-subtle)" }}>
                <h3 className="text-sm font-bold flex items-center gap-2 mb-4 text-orange-400">
                  <span className="transform -rotate-45 block"><ExternalLink size={16} /></span>
                  Delivery Options
                </h3>
                
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                       <CheckCircle size={16} className={sendViaEmail ? "text-orange-400" : "text-gray-500"} />
                       <span className="text-sm">Send via Email</span>
                    </div>
                    <button onClick={() => setSendViaEmail(!sendViaEmail)} className={`w-8 h-4 rounded-full p-0.5 transition ${sendViaEmail ? 'bg-orange-500' : 'bg-gray-600'}`}>
                      <div className={`bg-white w-3 h-3 rounded-full transform transition ${sendViaEmail ? 'translate-x-4' : 'translate-x-0'}`} />
                    </button>
                  </div>
                  {sendViaEmail && (
                    <div className="flex bg-black/20 rounded p-1 border" style={{ borderColor: 'var(--border-subtle)' }}>
                      <input type="text" placeholder="Enter Email Addresses" className="bg-transparent border-none outline-none text-xs w-full px-2" value={emailAddress} onChange={e => setEmailAddress(e.target.value)} />
                      <button className="text-orange-400 p-1"><Plus size={14}/></button>
                    </div>
                  )}

                  <div className="flex items-center justify-between mt-4">
                    <div className="flex items-center gap-2">
                       <CheckCircle size={16} className={saveToLocation ? "text-orange-400" : "text-gray-500"} />
                       <span className="text-sm">Save to Location</span>
                    </div>
                    <button onClick={() => setSaveToLocation(!saveToLocation)} className={`w-8 h-4 rounded-full p-0.5 transition ${saveToLocation ? 'bg-orange-500' : 'bg-gray-600'}`}>
                      <div className={`bg-white w-3 h-3 rounded-full transform transition ${saveToLocation ? 'translate-x-4' : 'translate-x-0'}`} />
                    </button>
                  </div>
                  {saveToLocation && (
                    <div className="flex bg-black/20 rounded p-1 border" style={{ borderColor: 'var(--border-subtle)' }}>
                      <input type="text" className="bg-transparent border-none outline-none text-xs w-full px-2" value={locationPath} onChange={e => setLocationPath(e.target.value)} />
                      <button className="text-orange-400 p-1"><Folder size={14}/></button>
                    </div>
                  )}

                  <div className="flex items-center gap-2 mt-4 cursor-pointer" onClick={() => setDownloadLink(!downloadLink)}>
                    <div className={`w-4 h-4 rounded border flex items-center justify-center ${downloadLink ? 'border-orange-400 bg-orange-400' : 'border-gray-500'}`}>
                      {downloadLink && <CheckCircle size={10} color="white" />}
                    </div>
                    <span className="text-sm text-gray-400 flex items-center gap-2">Download Link <Link size={12}/></span>
                  </div>

                  <div className="flex items-center gap-2 mt-2 cursor-pointer" onClick={() => setSlackNotif(!slackNotif)}>
                    <div className={`w-4 h-4 rounded border flex items-center justify-center ${slackNotif ? 'border-orange-400 bg-orange-400' : 'border-gray-500'}`}>
                      {slackNotif && <CheckCircle size={10} color="white" />}
                    </div>
                    <span className="text-sm text-gray-400 flex items-center gap-2"><MessageSquare size={12}/> Slack Notification</span>
                  </div>

                </div>
              </div>

              {/* Advanced Settings Bottom Bar */}
              <div className="col-span-1 md:col-span-2 bg-white/5 border rounded-xl p-4 flex flex-wrap items-center justify-between gap-4 mt-4" style={{ borderColor: "var(--border-subtle)" }}>
                <div className="flex items-center gap-6">
                  <span className="text-sm font-bold text-orange-400 flex items-center gap-2">⚙ Advanced Settings</span>
                  
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-gray-400">File Format:</span>
                    <select className="bg-transparent text-xs text-orange-400 outline-none border-b border-orange-400 pb-0.5" value={fileFormat} onChange={e => setFileFormat(e.target.value)}>
                      <option className="text-black" value="PDF">PDF</option>
                      <option className="text-black" value="CSV">CSV</option>
                      <option className="text-black" value="JSON">JSON</option>
                    </select>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-xs text-gray-400">Include Charts</span>
                    <button onClick={() => setIncludeCharts(!includeCharts)} className={`w-7 h-4 rounded-full p-0.5 transition ${includeCharts ? 'bg-orange-500' : 'bg-gray-600'}`}>
                      <div className={`bg-white w-3 h-3 rounded-full transform transition ${includeCharts ? 'translate-x-3' : 'translate-x-0'}`} />
                    </button>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-xs text-gray-400">Password Protect</span>
                    <button onClick={() => setPasswordProtect(!passwordProtect)} disabled={fileFormat !== "PDF"} className={`w-7 h-4 rounded-full p-0.5 transition ${passwordProtect ? 'bg-orange-500' : 'bg-gray-600'} ${fileFormat !== "PDF" ? "opacity-50" : ""}`}>
                      <div className={`bg-white w-3 h-3 rounded-full transform transition ${passwordProtect ? 'translate-x-3' : 'translate-x-0'}`} />
                    </button>
                  </div>
                </div>

                <button 
                  className="bg-yellow-500 hover:bg-yellow-600 text-black px-6 py-2 rounded-lg font-bold text-sm flex items-center gap-2"
                  onClick={handleGenerate}
                  disabled={generating}
                >
                  {generating ? <Loader2 size={16} className="animate-spin" /> : <FileText size={16} />}
                  Generate Report
                </button>
              </div>

            </div>
          ) : (
            /* SCHEDULE MODE */
            <div className="grid grid-cols-1 md:grid-cols-2 gap-12">
              <div className="space-y-6">
                <div>
                  <label className="block text-xs font-bold mb-2">Report Type</label>
                  <select
                    className="w-full p-3 rounded border text-sm"
                    style={{ background: "transparent", borderColor: "var(--accent-gold)", color: "var(--text-primary)", outline: "none" }}
                    value={reportType}
                    onChange={(e) => setReportType(e.target.value)}
                  >
                    {reportOptions.map(o => (
                      <option key={o.value} value={o.value} disabled={o.disabled} className="text-black">{o.label}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-bold mb-2">Frequency</label>
                  <select
                    className="w-full p-3 rounded border text-sm"
                    style={{ background: "transparent", borderColor: "var(--border-subtle)", color: "var(--text-primary)", outline: "none" }}
                    value={frequency}
                    onChange={(e) => setFrequency(e.target.value)}
                  >
                    <option className="text-black">Weekly</option>
                    <option className="text-black">Monthly</option>
                    <option className="text-black">Daily</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-bold mb-2">Select Assets</label>
                  <select
                    className="w-full p-3 rounded border text-sm"
                    style={{ background: "transparent", borderColor: "var(--border-subtle)", color: "var(--text-primary)", outline: "none" }}
                    value={targetAssets}
                    onChange={(e) => setTargetAssets(e.target.value)}
                  >
                    <option className="text-black">All Assets</option>
                    <option className="text-black">Critical Only</option>
                  </select>
                </div>

                <div>
                  <label className="flex items-center gap-2 text-xs font-bold mb-3">
                    <CheckCircle size={14} className="text-orange-400"/> Include Sections
                  </label>
                  <div className="flex flex-wrap gap-3">
                    {Object.entries(sections).map(([key, val]) => (
                      <label key={key} className="flex items-center gap-1.5 cursor-pointer bg-white/5 px-3 py-1.5 rounded-full border" style={{ borderColor: 'var(--border-subtle)' }}>
                        <div className={`w-3 h-3 rounded flex items-center justify-center ${val ? 'bg-orange-400' : 'bg-gray-600'}`}>
                          {val && <CheckCircle size={8} color="white" />}
                        </div>
                        <span className="text-xs capitalize flex-1">{key.replace('_', ' ')}</span>
                      </label>
                    ))}
                  </div>
                </div>
              </div>

              <div className="space-y-6">
                {/* Schedule Details block */}
                <div className="border-l border-dashed border-gray-600 pl-6 space-y-4 relative">
                  <h3 className="text-sm font-bold flex items-center gap-2 mb-4 text-orange-400">
                    <CalendarDays size={16} /> Schedule Details
                  </h3>
                  
                  <div>
                    <label className="block text-xs text-gray-400 mb-1">Date</label>
                    <div className="flex items-center border rounded p-2" style={{ borderColor: 'var(--border-subtle)', background: 'var(--bg-card)' }}>
                      <CalendarDays size={14} className="text-orange-400 mr-2" />
                      <input type="date" className="bg-transparent text-sm w-full outline-none text-white appearance-none" value={scheduleDate} onChange={e => setScheduleDate(e.target.value)} />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs text-gray-400 mb-1">Time</label>
                    <div className="flex items-center border rounded p-2" style={{ borderColor: 'var(--border-subtle)', background: 'var(--bg-card)' }}>
                      <Clock size={14} className="text-orange-400 mr-2" />
                      <input type="time" className="bg-transparent text-sm w-full outline-none text-white" value={scheduleTime} onChange={e => setScheduleTime(e.target.value)} />
                    </div>
                    <p className="text-[10px] text-gray-500 mt-1">Time Zone: {timeZone}</p>
                  </div>
                </div>

                {/* Delivery Options Block */}
                <div className="bg-white/5 border rounded-xl p-5 relative mt-4 shadow-xl shadow-black/50" style={{ borderColor: "var(--border-subtle)" }}>
                  <h3 className="text-sm font-bold flex items-center gap-2 mb-4 text-orange-400">
                    <span className="transform -rotate-45 block"><ExternalLink size={16} /></span>
                    Delivery Options
                  </h3>
                  
                  <div className="space-y-3">
                    <label className="flex items-center gap-2 text-sm font-semibold">
                      <div className={`w-4 h-4 rounded border flex items-center justify-center ${emailChecked ? 'border-orange-400 bg-orange-400' : 'border-gray-500'}`} onClick={() => setEmailChecked(!emailChecked)}>
                        {emailChecked && <CheckCircle size={10} color="white" />}
                      </div>
                      Email
                      <div className="flex-1 flex items-center border rounded ml-2 bg-black/20" style={{ borderColor: 'var(--border-subtle)' }}>
                        <input type="text" className="bg-transparent border-none outline-none text-xs w-full p-1.5" value={schedEmail} onChange={e => setSchedEmail(e.target.value)} />
                        <span className="text-orange-400 px-2"><Plus size={12}/></span>
                      </div>
                    </label>

                    <label className="flex items-center gap-2 text-sm font-semibold">
                      <div className={`w-4 h-4 rounded border flex items-center justify-center ${schedSaveChecked ? 'border-orange-400 bg-orange-400' : 'border-gray-500'}`} onClick={() => setSchedSaveChecked(!schedSaveChecked)}>
                        {schedSaveChecked && <CheckCircle size={10} color="white" />}
                      </div>
                      Save to Location
                      <div className="flex-1 flex items-center border rounded ml-2 bg-black/20" style={{ borderColor: 'var(--border-subtle)' }}>
                        <input type="text" className="bg-transparent border-none outline-none text-xs w-full p-1.5" value={schedLocation} onChange={e => setSchedLocation(e.target.value)} />
                      </div>
                    </label>

                    <label className="flex items-center gap-2 text-sm font-semibold cursor-pointer" onClick={() => setSchedDownload(!schedDownload)}>
                      <div className={`w-4 h-4 rounded border flex items-center justify-center ${schedDownload ? 'border-orange-400 bg-orange-400' : 'border-gray-500'}`}>
                        {schedDownload && <CheckCircle size={10} color="white" />}
                      </div>
                      Download Link <Link size={12} className="ml-auto text-orange-400"/>
                    </label>
                  </div>
                  
                  <div className="mt-6 flex justify-end">
                    <button 
                      className="bg-orange-500 hover:bg-orange-600 text-white px-6 py-2 rounded-full font-bold text-sm flex items-center gap-2"
                      onClick={handleSchedule}
                      disabled={generating}
                    >
                      {generating ? <Loader2 size={16} className="animate-spin" /> : null}
                      Schedule Report →
                    </button>
                  </div>
                </div>

              </div>
            </div>
          )}

          {/* ─── Active Schedules List ─── */}
          {isScheduled && (
            <div className="mt-8 border-t pt-6" style={{ borderColor: "var(--border-subtle)" }}>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-bold flex items-center gap-2" style={{ color: "var(--text-primary)" }}>
                  <CalendarDays size={18} className="text-orange-400" /> Active Schedules
                </h3>
                <button onClick={fetchSchedules} className="text-xs text-gray-400 hover:text-orange-400 flex items-center gap-1 transition">
                  <RefreshCw size={12} className={loadingSchedules ? "animate-spin" : ""} /> Refresh
                </button>
              </div>

              {loadingSchedules ? (
                <div className="flex items-center gap-2 text-sm text-gray-400 py-4">
                  <Loader2 size={14} className="animate-spin" /> Loading schedules...
                </div>
              ) : schedules.length === 0 ? (
                <div className="text-sm text-gray-500 py-4 text-center">
                  No scheduled reports yet. Create one above to get started.
                </div>
              ) : (
                <div className="space-y-3">
                  {schedules.map((s: any) => (
                    <div key={s.id} className="flex items-center justify-between bg-white/5 border rounded-xl p-4 group hover:border-orange-400/30 transition" style={{ borderColor: "var(--border-subtle)" }}>
                      <div className="flex items-center gap-4 flex-1 min-w-0">
                        <div className="p-2 rounded-lg bg-orange-500/15 text-orange-400 shrink-0">
                          <CalendarDays size={18} />
                        </div>
                        <div className="min-w-0">
                          <p className="text-sm font-semibold truncate" style={{ color: "var(--text-primary)" }}>
                            {reportOptions.find(o => o.value === s.report_type)?.label || s.report_type}
                          </p>
                          <div className="flex items-center gap-3 mt-1 text-[11px] text-gray-400">
                            <span className="flex items-center gap-1">
                              <Clock size={10} />
                              {s.schedule_date ? new Date(s.schedule_date).toLocaleString() : "—"}
                            </span>
                            <span className="px-1.5 py-0.5 rounded bg-orange-500/15 text-orange-400 font-bold">
                              {s.frequency}
                            </span>
                            <span>{s.target_assets}</span>
                          </div>
                          <div className="flex items-center gap-3 mt-1 text-[10px] text-gray-500">
                            {s.delivery_email && <span>📧 {s.delivery_email}</span>}
                            {s.delivery_location && <span>📁 {s.delivery_location}</span>}
                            {s.download_link && <span>🔗 Download</span>}
                          </div>
                        </div>
                      </div>
                      <button
                        onClick={() => handleDeleteSchedule(s.id)}
                        className="p-2 rounded-lg text-gray-500 hover:text-red-400 hover:bg-red-400/10 transition opacity-0 group-hover:opacity-100"
                        title="Delete schedule"
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
      
      {currentTime && (
        <div className="fixed bottom-4 left-4 flex flex-col gap-1 items-start text-[10px] uppercase font-bold tracking-widest opacity-50 z-50">
          <span className="flex items-center gap-1.5"><Clock size={10} /> Local System Time</span>
          <span className="text-xs text-orange-400 font-mono tracking-tight">{currentTime.toLocaleString()}</span>
        </div>
      )}
    </div>
  );
}
