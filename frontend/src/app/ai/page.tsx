"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import {
  useAIChat, useAIStatus, useAIModels, useRefreshEmbeddings,
  useUpdateAISettings, useAgentStream, useAgentStatus, useScans,
  type AgentEvent,
} from "@/lib/hooks";
import { ScanSelector } from "@/components/ui";
import { Bot, Send, Loader2, Search, RefreshCw, Settings, X,
  Cpu, Cloud, ChevronDown, ChevronRight, Zap, Database, Globe } from "lucide-react";
import type { ChatMessage } from "@/lib/types";

const STARTER_QUERIES = [
  "Which assets are currently exposed to HNDL attacks?",
  "Generate a board-level summary of our quantum risk position",
  "What is our current RBI IT Framework 2023 compliance status?",
  "Which vendors have no PQC roadmap and what should we do?",
  "Show me the top algorithms in our CBOM that need to be replaced",
  "What is our estimated migration timeline at the current pace?",
];

interface TraceStep {
  type: "thought" | "tool";
  content: string;
}

interface ExtendedMessage extends ChatMessage {
  trace?: TraceStep[];
  isStreaming?: boolean;
}

type ChatMode = "agent" | "rag" | "sql";

export default function AIAssistantPage() {
  const [messages, setMessages] = useState<ExtendedMessage[]>([]);
  const [input, setInput] = useState("");
  const [showSettings, setShowSettings] = useState(false);
  const [mode, setMode] = useState<ChatMode>("agent");
  const [expandedTraces, setExpandedTraces] = useState<Set<number>>(new Set());
  const [scanId, setScanId] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const aiChat = useAIChat();
  const { data: aiStatus } = useAIStatus();
  const { data: aiModels } = useAIModels();
  const { data: agentStatus } = useAgentStatus();
  const { data: scans } = useScans();
  const refreshEmbeddings = useRefreshEmbeddings();
  const agentStream = useAgentStream();

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const isLoading = aiChat.isPending || agentStream.isPending;

  const sendMessage = useCallback(async (text: string) => {
    if (!text.trim() || isLoading) return;
    setInput("");

    const userMsg: ExtendedMessage = {
      role: "user",
      content: text,
      timestamp: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMsg]);

    if (mode === "agent") {
      // Streaming ReAct agent
      const placeholderIdx = messages.length + 1;
      let answerBuf = "";
      const traceSteps: TraceStep[] = [];

      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "", isStreaming: true, trace: [], timestamp: new Date().toISOString() },
      ]);

      const history = messages
        .filter(m => m.role === "user" || m.role === "assistant")
        .map(m => ({ role: m.role, content: m.content }));

      try {
        await agentStream.mutateAsync({
          message: text,
          history,
          scan_id: scanId,
          onEvent: (event: AgentEvent) => {
            if (event.type === "thought" || event.type === "tool") {
              traceSteps.push({ type: event.type, content: event.content });
              setMessages((prev) => {
                const copy = [...prev];
                const last = copy[copy.length - 1];
                if (last && last.role === "assistant") {
                  copy[copy.length - 1] = { ...last, trace: [...traceSteps] };
                }
                return copy;
              });
            } else if (event.type === "answer") {
              answerBuf += event.content;
              setMessages((prev) => {
                const copy = [...prev];
                const last = copy[copy.length - 1];
                if (last && last.role === "assistant") {
                  copy[copy.length - 1] = { ...last, content: answerBuf, isStreaming: true };
                }
                return copy;
              });
            } else if (event.type === "done") {
              setMessages((prev) => {
                const copy = [...prev];
                const last = copy[copy.length - 1];
                if (last && last.role === "assistant") {
                  copy[copy.length - 1] = { ...last, isStreaming: false };
                }
                return copy;
              });
            } else if (event.type === "error") {
              setMessages((prev) => {
                const copy = [...prev];
                const last = copy[copy.length - 1];
                if (last && last.role === "assistant") {
                  copy[copy.length - 1] = { ...last, content: `Error: ${event.content}`, isStreaming: false };
                }
                return copy;
              });
            }
          },
        });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "Unknown error";
        setMessages((prev) => {
          const copy = [...prev];
          const last = copy[copy.length - 1];
          if (last?.role === "assistant") {
            copy[copy.length - 1] = { ...last, content: `Agent error: ${msg}`, isStreaming: false };
          }
          return copy;
        });
      }
    } else {
      // Legacy RAG/SQL chat
      try {
        const data = await aiChat.mutateAsync({ message: text, mode });
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: data.response,
            mode_used: data.mode_used,
            sources: data.sources,
            timestamp: new Date().toISOString(),
          },
        ]);
      } catch {
        setMessages((prev) => [
          ...prev,
          { role: "assistant", content: "Request failed. Please try again.", timestamp: new Date().toISOString() },
        ]);
      }
    }
  }, [messages, input, mode, isLoading, aiChat, agentStream]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage(input);
    }
  };

  const toggleTrace = (idx: number) => {
    setExpandedTraces(prev => {
      const next = new Set(prev);
      next.has(idx) ? next.delete(idx) : next.add(idx);
      return next;
    });
  };

  const modeOptions: { value: ChatMode; label: string; icon: React.ReactNode; desc: string; badge?: string }[] = [
    { value: "agent", label: "ReAct Agent", icon: <Zap size={14}/>, desc: "Reasoning + tools", badge: "RECOMMENDED" },
    { value: "rag", label: "RAG Search", icon: <Database size={14}/>, desc: "Knowledge base" },
    { value: "sql", label: "SQL Query", icon: <Search size={14}/>, desc: "Scan data tables" },
  ];

  return (
    <div className="flex h-[calc(100vh-64px)] overflow-hidden" style={{ background: "var(--bg-primary)" }}>
      {/* ── Sidebar ── */}
      <div className="w-64 border-r flex flex-col shrink-0" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
        {/* Agent Status */}
        <div className="p-4 border-b" style={{ borderColor: "var(--border-subtle)" }}>
          <div className="flex items-center gap-2 mb-3">
            <Bot size={18} className="text-yellow-400" />
            <span className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>QuShield AI</span>
          </div>
          <div className="mb-3">
            <p className="text-[10px] font-bold uppercase tracking-widest mb-1.5" style={{ color: "var(--text-muted)" }}>Scan Scope</p>
            <ScanSelector scans={scans} scanId={scanId} onChange={setScanId} className="w-full" />
            {scanId && (
              <p className="text-[9px] mt-1" style={{ color: "var(--text-muted)" }}>Agent will only query data from selected scan.</p>
            )}
          </div>
          <div className="space-y-1 text-[11px]" style={{ color: "var(--text-muted)" }}>
            <div className="flex justify-between">
              <span>Agent</span>
              <span className={`font-bold ${agentStatus?.available ? "text-green-400" : "text-red-400"}`}>
                {agentStatus?.available ? "ONLINE" : "OFFLINE"}
              </span>
            </div>
            {agentStatus?.available && (
              <div className="flex justify-between">
                <span>Model</span>
                <span className="text-yellow-400 font-mono text-[10px]">llama-3.3-70b</span>
              </div>
            )}
            <div className="flex justify-between">
              <span>AI Status</span>
              <span className={`font-bold ${aiStatus?.deployment_mode ? "text-green-400" : "text-yellow-400"}`}>
                {(aiStatus?.deployment_mode || "—").toUpperCase()}
              </span>
            </div>
          </div>
        </div>

        {/* Mode Selection */}
        <div className="p-4 border-b" style={{ borderColor: "var(--border-subtle)" }}>
          <p className="text-[10px] font-bold uppercase tracking-widest mb-3" style={{ color: "var(--text-muted)" }}>Chat Mode</p>
          <div className="space-y-1">
            {modeOptions.map(opt => (
              <button
                key={opt.value}
                onClick={() => setMode(opt.value)}
                className={`w-full flex items-center gap-2 p-2 rounded-lg text-left transition text-[12px] ${mode === opt.value ? "bg-yellow-500/20 text-yellow-400" : "hover:bg-white/5 text-gray-400"}`}
              >
                {opt.icon}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1">
                    <span className="font-semibold">{opt.label}</span>
                    {opt.badge && <span className="text-[8px] px-1 rounded bg-yellow-500/30 text-yellow-400 font-bold">{opt.badge}</span>}
                  </div>
                  <div className="text-[10px] opacity-60">{opt.desc}</div>
                </div>
                {mode === opt.value && <div className="w-1.5 h-1.5 rounded-full bg-yellow-400 shrink-0" />}
              </button>
            ))}
          </div>
        </div>

        {/* Agent Tools */}
        {mode === "agent" && agentStatus?.features && (
          <div className="p-4 border-b" style={{ borderColor: "var(--border-subtle)" }}>
            <p className="text-[10px] font-bold uppercase tracking-widest mb-2" style={{ color: "var(--text-muted)" }}>Active Tools</p>
            <div className="space-y-1">
              {agentStatus.features.map((f: string) => (
                <div key={f} className="flex items-center gap-2 text-[11px] text-green-400">
                  <div className="w-1.5 h-1.5 rounded-full bg-green-400" />
                  {f.replace("_", " ")}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Starter Queries */}
        <div className="p-4 flex-1 overflow-y-auto">
          <p className="text-[10px] font-bold uppercase tracking-widest mb-2" style={{ color: "var(--text-muted)" }}>Example Queries</p>
          <div className="space-y-1">
            {STARTER_QUERIES.map((q) => (
              <button
                key={q}
                onClick={() => { setInput(q); inputRef.current?.focus(); }}
                className="w-full text-left text-[11px] p-2 rounded-lg hover:bg-white/5 transition leading-tight"
                style={{ color: "var(--text-secondary)" }}
              >
                {q}
              </button>
            ))}
          </div>
        </div>

        {/* Settings */}
        <div className="p-4 border-t" style={{ borderColor: "var(--border-subtle)" }}>
          <button
            onClick={() => { refreshEmbeddings.mutate(); }}
            disabled={refreshEmbeddings.isPending}
            className="w-full flex items-center gap-2 p-2 rounded-lg hover:bg-white/5 text-[11px] text-gray-400 hover:text-yellow-400 transition"
          >
            <RefreshCw size={12} className={refreshEmbeddings.isPending ? "animate-spin" : ""} />
            Refresh Embeddings
          </button>
        </div>
      </div>

      {/* ── Chat Area ── */}
      <div className="flex flex-col flex-1 min-w-0">
        {/* Header */}
        <div className="px-6 py-4 border-b flex items-center justify-between shrink-0" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-yellow-500/20">
              <Bot size={18} className="text-yellow-400" />
            </div>
            <div>
              <h1 className="text-base font-bold" style={{ color: "var(--text-primary)" }}>
                QuShield AI Assistant
                <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded bg-yellow-500/20 text-yellow-400 font-bold align-middle">
                  {mode === "agent" ? "ReAct Agent" : mode.toUpperCase()}
                </span>
              </h1>
              <p className="text-[11px]" style={{ color: "var(--text-muted)" }}>
                {mode === "agent"
                  ? "Reasoning agent with RAG, SQL, web search, and report access"
                  : mode === "rag" ? "Semantic search over knowledge base and scan data"
                  : "Natural language queries over your scan database"}
              </p>
            </div>
          </div>
          <button
            onClick={() => setMessages([])}
            className="text-[11px] text-gray-500 hover:text-red-400 transition px-2 py-1 rounded"
          >
            Clear chat
          </button>
        </div>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {messages.length === 0 && (
            <div className="flex flex-col items-center justify-center h-full text-center gap-4 opacity-60">
              <Bot size={48} className="text-yellow-400" />
              <div>
                <p className="text-base font-bold" style={{ color: "var(--text-primary)" }}>QuShield AI Ready</p>
                <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
                  Ask about quantum risk, compliance status, migration priorities, or specific assets
                </p>
              </div>
            </div>
          )}

          {messages.map((msg, idx) => (
            <div key={idx} className={`flex gap-3 ${msg.role === "user" ? "flex-row-reverse" : "flex-row"}`}>
              {/* Avatar */}
              <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${msg.role === "user" ? "bg-yellow-500/20 text-yellow-400" : "bg-blue-500/20 text-blue-400"}`}>
                {msg.role === "user" ? "U" : <Bot size={14} />}
              </div>

              <div className={`max-w-[80%] space-y-2 ${msg.role === "user" ? "items-end" : "items-start"} flex flex-col`}>
                {/* Reasoning Trace (agent mode) */}
                {msg.role === "assistant" && msg.trace && msg.trace.length > 0 && (
                  <div className="w-full">
                    <button
                      onClick={() => toggleTrace(idx)}
                      className="flex items-center gap-1.5 text-[10px] text-gray-500 hover:text-yellow-400 transition mb-1"
                    >
                      {expandedTraces.has(idx) ? <ChevronDown size={10}/> : <ChevronRight size={10}/>}
                      Reasoning trace ({msg.trace.length} steps)
                    </button>
                    {expandedTraces.has(idx) && (
                      <div className="bg-black/40 border rounded-lg p-3 space-y-1.5 text-[10px] font-mono" style={{ borderColor: "var(--border-subtle)" }}>
                        {msg.trace.map((step, si) => (
                          <div key={si} className={`flex gap-2 ${step.type === "thought" ? "text-yellow-400/80" : "text-blue-400/80"}`}>
                            <span className="shrink-0 font-bold">{step.type === "thought" ? "💭" : "🔧"}</span>
                            <span className="whitespace-pre-wrap break-words">{step.content}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Message bubble */}
                <div
                  className={`rounded-2xl px-4 py-3 text-sm leading-relaxed ${
                    msg.role === "user"
                      ? "bg-yellow-500/15 border border-yellow-500/20"
                      : "border"
                  }`}
                  style={{
                    background: msg.role === "assistant" ? "var(--bg-card)" : undefined,
                    borderColor: msg.role === "assistant" ? "var(--border-subtle)" : undefined,
                    color: "var(--text-primary)",
                  }}
                >
                  <div className="whitespace-pre-wrap break-words">{msg.content}</div>
                  {msg.isStreaming && (
                    <span className="inline-block w-1.5 h-4 bg-yellow-400 animate-pulse ml-0.5 align-middle" />
                  )}
                </div>

                {/* Meta */}
                {msg.role === "assistant" && (msg.mode_used || msg.sources?.length) && (
                  <div className="flex flex-wrap gap-2 text-[10px] text-gray-500 px-1">
                    {msg.mode_used && (
                      <span className="px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-400 font-bold uppercase">{msg.mode_used}</span>
                    )}
                    {msg.sources?.map((s, si) => (
                      <span key={si} className="px-1.5 py-0.5 rounded bg-white/5 truncate max-w-[200px]">{s}</span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}
          <div ref={messagesEndRef} />
        </div>

        {/* Input */}
        <div className="p-4 border-t shrink-0" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
          <div className="flex gap-3 items-end">
            <textarea
              ref={inputRef}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={
                mode === "agent" ? "Ask anything — the agent will reason, search, and query as needed…"
                : mode === "rag" ? "Search the knowledge base…"
                : "Ask a data question (e.g. 'How many critical assets do I have?')"
              }
              rows={2}
              disabled={isLoading}
              className="flex-1 resize-none rounded-xl border px-4 py-3 text-sm focus:outline-none focus:ring-1 focus:ring-yellow-400 transition disabled:opacity-50"
              style={{ background: "var(--bg-primary)", borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}
            />
            <button
              onClick={() => sendMessage(input)}
              disabled={isLoading || !input.trim()}
              className="p-3 rounded-xl bg-yellow-500 hover:bg-yellow-400 text-black font-bold transition disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
            >
              {isLoading ? <Loader2 size={18} className="animate-spin" /> : <Send size={18} />}
            </button>
          </div>
          <p className="text-[10px] mt-2 text-gray-600 text-center">
            {mode === "agent"
              ? "ReAct agent — uses RAG, SQL, web search, and report tools automatically"
              : "Press Enter to send, Shift+Enter for new line"}
          </p>
        </div>
      </div>
    </div>
  );
}
