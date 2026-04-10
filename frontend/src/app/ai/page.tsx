"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { useAIChat, useAIStatus, useAIModels, useRefreshEmbeddings, useUpdateAISettings } from "@/lib/hooks";
import { EmptyState, Skeleton } from "@/components/ui";
import { Bot, Send, Loader2, Database, Search, RefreshCw, Settings, X, Cpu, Cloud } from "lucide-react";
import type { ChatMessage } from "@/lib/types";

const STARTER_QUERIES = [
  "Which of our assets are currently exposed to HNDL attacks?",
  "Generate a board-level summary of our quantum risk position",
  "Which third-party vendors have no PQC roadmap?",
  "What is our estimated migration timeline at current pace?",
];

export default function AIAssistantPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [showSettings, setShowSettings] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const aiChat = useAIChat();
  const { data: aiStatus } = useAIStatus();
  const { data: aiModels } = useAIModels();
  const refreshEmbeddings = useRefreshEmbeddings();
  const updateSettings = useUpdateAISettings();

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const sendMessage = useCallback(async (text: string) => {
    if (!text.trim()) return;

    const userMsg: ChatMessage = {
      role: "user",
      content: text,
      timestamp: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");

    try {
      const data = await aiChat.mutateAsync({ message: text });
      const assistantMsg: ChatMessage = {
        role: "assistant",
        content: data.response,
        mode_used: data.mode_used,
        sources: data.sources,
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch {
      const errorMsg: ChatMessage = {
        role: "assistant",
        content: "Sorry, I encountered an error processing your request. Please check that the AI backend is running and try again.",
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, errorMsg]);
    }
  }, [aiChat]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    sendMessage(input);
  };

  return (
    <div className="animate-fade-in h-[calc(100vh-var(--header-height)-48px)] flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between mb-4 flex-shrink-0">
        <div>
          <h1 className="text-2xl font-black" style={{ color: "var(--text-primary)" }}>
            AI Security Analyst
          </h1>
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            Query your scan data using natural language — powered by RAG + SQL AI agents
          </p>
        </div>
        <div className="flex items-center gap-2">
          {/* AI Status Indicator */}
          {aiStatus && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
              {aiStatus.deployment_mode === "secure" ? (
                <Cpu size={12} style={{ color: "var(--risk-ready)" }} />
              ) : (
                <Cloud size={12} style={{ color: "var(--accent-gold)" }} />
              )}
              <span style={{ color: "var(--text-secondary)" }}>
                {aiStatus.deployment_mode === "secure" ? "Local" : "Cloud"} • {aiStatus.active_tier}
              </span>
            </div>
          )}
          <button
            className="btn-outline text-xs flex items-center gap-1"
            onClick={() => refreshEmbeddings.mutate()}
            disabled={refreshEmbeddings.isPending}
          >
            <RefreshCw size={12} className={refreshEmbeddings.isPending ? "animate-spin" : ""} />
            Sync Data
          </button>
          <button
            className="btn-outline text-xs flex items-center gap-1"
            onClick={() => setShowSettings(!showSettings)}
          >
            <Settings size={12} /> Settings
          </button>
        </div>
      </div>

      {/* Settings Panel */}
      {showSettings && (
        <div className="glass-card-static p-5 mb-4 flex-shrink-0 animate-fade-in">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>AI Configuration</h3>
            <button onClick={() => setShowSettings(false)} style={{ color: "var(--text-muted)" }}><X size={16} /></button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: "var(--text-muted)" }}>
                Deployment Mode
              </label>
              <div className="flex gap-2">
                {["secure", "cloud"].map((mode) => (
                  <button
                    key={mode}
                    className="px-4 py-2 rounded-lg text-xs font-bold uppercase transition-all"
                    style={{
                      background: aiStatus?.deployment_mode === mode ? "var(--accent-gold-dim)" : "var(--bg-card)",
                      color: aiStatus?.deployment_mode === mode ? "var(--accent-gold)" : "var(--text-muted)",
                      border: `1px solid ${aiStatus?.deployment_mode === mode ? "var(--accent-gold)" : "var(--border-subtle)"}`,
                    }}
                    onClick={() => updateSettings.mutate({ deployment_mode: mode })}
                  >
                    {mode === "secure" ? "🔒 Local" : "☁️ Cloud"}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: "var(--text-muted)" }}>
                Tier
              </label>
              <div className="flex gap-2">
                {["free", "professional", "enterprise"].map((tier) => (
                  <button
                    key={tier}
                    className="px-3 py-2 rounded-lg text-xs font-bold capitalize transition-all"
                    style={{
                      background: aiStatus?.active_tier === tier ? "var(--accent-gold-dim)" : "var(--bg-card)",
                      color: aiStatus?.active_tier === tier ? "var(--accent-gold)" : "var(--text-muted)",
                      border: `1px solid ${aiStatus?.active_tier === tier ? "var(--accent-gold)" : "var(--border-subtle)"}`,
                    }}
                    onClick={() => updateSettings.mutate({ ai_tier: tier })}
                  >
                    {tier}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: "var(--text-muted)" }}>
                Available Models
              </label>
              <div className="flex flex-wrap gap-1">
                {aiModels?.models.map((m) => (
                  <span key={m} className="px-2 py-1 rounded text-[10px] font-mono" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)", color: "var(--text-secondary)" }}>
                    {m}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Chat Area */}
      <div className="flex-1 flex flex-col glass-card-static overflow-hidden">
        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {messages.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full">
              <div className="w-16 h-16 rounded-2xl flex items-center justify-center mb-6" style={{ background: "var(--accent-gold-dim)" }}>
                <Bot size={32} style={{ color: "var(--accent-gold)" }} />
              </div>
              <h2 className="text-lg font-bold mb-2" style={{ color: "var(--text-primary)" }}>
                QuShield AI Security Analyst
              </h2>
              <p className="text-sm text-center max-w-md mb-8" style={{ color: "var(--text-muted)" }}>
                Ask questions about your quantum security posture, asset vulnerabilities, compliance status, and migration readiness.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-w-2xl w-full">
                {STARTER_QUERIES.map((q) => (
                  <button
                    key={q}
                    className="text-left p-4 rounded-xl text-sm transition-all hover:scale-[1.02]"
                    style={{
                      background: "var(--bg-card)",
                      border: "1px solid var(--border-subtle)",
                      color: "var(--text-secondary)",
                    }}
                    onClick={() => sendMessage(q)}
                  >
                    <Search size={14} className="inline mr-2" style={{ color: "var(--accent-gold)" }} />
                    {q}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            messages.map((msg, i) => (
              <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
                <div
                  className="max-w-[75%] rounded-2xl px-5 py-3"
                  style={{
                    background: msg.role === "user"
                      ? "linear-gradient(135deg, #a4123f, #7d002c)"
                      : "var(--bg-card)",
                    color: msg.role === "user" ? "#fff" : "var(--text-primary)",
                    border: msg.role === "assistant" ? "1px solid var(--border-subtle)" : "none",
                  }}
                >
                  {/* Mode indicator */}
                  {msg.mode_used && (
                    <div className="flex items-center gap-1 mb-2">
                      <span
                        className="px-2 py-0.5 rounded text-[10px] font-bold uppercase"
                        style={{
                          background: msg.mode_used === "sql" ? "rgba(59,130,246,0.15)" : "rgba(139,92,246,0.15)",
                          color: msg.mode_used === "sql" ? "#3b82f6" : "#8b5cf6",
                        }}
                      >
                        <Database size={10} className="inline mr-1" />
                        {msg.mode_used === "sql" ? "SQL Engine" : "ChromaDB RAG"}
                      </span>
                    </div>
                  )}
                  <div className="text-sm leading-relaxed whitespace-pre-wrap">{msg.content}</div>
                  {msg.sources && msg.sources.length > 0 && (
                    <div className="mt-3 pt-2" style={{ borderTop: "1px solid var(--border-subtle)" }}>
                      <span className="text-[10px] font-bold uppercase" style={{ color: "var(--text-muted)" }}>Sources:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {msg.sources.map((s, j) => (
                          <span key={j} className="px-2 py-0.5 rounded text-[10px] font-mono" style={{ background: "var(--bg-primary)", color: "var(--text-muted)" }}>
                            {s}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ))
          )}
          {aiChat.isPending && (
            <div className="flex justify-start">
              <div className="rounded-2xl px-5 py-3 flex items-center gap-2" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}>
                <Loader2 size={16} className="animate-spin" style={{ color: "var(--accent-gold)" }} />
                <span className="text-sm" style={{ color: "var(--text-muted)" }}>Analyzing data…</span>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Input Bar */}
        <form
          onSubmit={handleSubmit}
          className="flex-shrink-0 p-4 flex items-center gap-3"
          style={{ borderTop: "1px solid var(--border-subtle)" }}
        >
          <input
            type="text"
            className="flex-1 py-3 px-5 rounded-xl text-sm"
            style={{
              background: "var(--bg-primary)",
              border: "1px solid var(--border-subtle)",
              color: "var(--text-primary)",
              outline: "none",
            }}
            placeholder="Ask about your quantum security posture…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={aiChat.isPending}
          />
          <button
            type="submit"
            className="btn-primary p-3 rounded-xl"
            disabled={!input.trim() || aiChat.isPending}
          >
            <Send size={18} />
          </button>
        </form>
      </div>
    </div>
  );
}
