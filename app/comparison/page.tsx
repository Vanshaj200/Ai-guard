"use client"
import React, { useState, useEffect } from 'react'
import Link from 'next/link'
import { benchmarkDataService, ModelComparisonResult } from '@/lib/data-service'
import { Award, BarChart2, TrendingUp, Info, Play } from 'lucide-react'
import {
  Radar,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from 'recharts'

const FAMILY_KEYS = [
  'direct_injection',
  'content_injection',
  'exfiltration',
  'goal_diversion',
  'memory_poisoning',
  'autonomy',
  'planning',
  'tool_security',
]

const pct = (v: number | null | undefined) => (v === null || v === undefined ? '—' : `${v}%`)

export default function ModelComparisonPage() {
  const [models, setModels] = useState<ModelComparisonResult[]>([])
  const [untested, setUntested] = useState<{ agentId: string; modelName: string }[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    benchmarkDataService
      .fetchLeaderboard()
      .then(data => {
        setModels(data.models)
        setUntested(data.untested)
      })
      .finally(() => setLoading(false))
  }, [])

  const radarModels = models.slice(0, 5)
  const radarData = FAMILY_KEYS.map(fam => {
    const entry: Record<string, string | number | null> = {
      family: fam.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
    }
    radarModels.forEach(m => {
      entry[m.modelName] = m.familyScores[fam] ?? null
    })
    return entry
  })

  const outcomeData = models.map(m => ({
    name: m.modelName.split(' ')[0],
    Resisted: m.overallScore,
    Compromised: m.asr,
  }))

  const colors = ['#2563eb', '#10b981', '#f59e0b', '#f43f5e', '#6366f1']

  if (loading) return <div className="p-8 text-center text-xs">Loading Model Leaderboard & Comparison Matrix...</div>

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="border-b border-[var(--border-subtle)] pb-4">
        <div className="flex items-center gap-2 text-xs font-semibold text-amber-500 uppercase tracking-wider mb-1">
          <Award className="h-4 w-4 text-amber-500" /> Academic Benchmark Leaderboard
        </div>
        <h1 className="text-2xl font-bold text-[var(--text-primary)] tracking-tight">Model Security Leaderboard & Comparison</h1>
        <p className="text-xs text-[var(--text-secondary)] mt-0.5">
          Every number below is computed from stored benchmark runs. For each attack family, a model&apos;s most recent run
          covering that family is used. Models tested on all 8 families rank above partial runs.
        </p>
      </div>

      {/* Leaderboard Table */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-[var(--text-primary)] uppercase tracking-wider">
            Overall Model Ranking Matrix
          </h2>
          <span className="font-mono text-[11px] text-[var(--text-muted)]">CitingKey: aiguard2024</span>
        </div>

        {models.length === 0 ? (
          <div className="research-card text-xs text-[var(--text-secondary)] flex items-center justify-between gap-3">
            <span>No completed benchmark runs yet. Run one to populate the leaderboard.</span>
            <Link href="/benchmark" className="inline-flex items-center gap-1.5 font-semibold text-[var(--primary)] hover:underline">
              <Play className="h-3.5 w-3.5" /> Run Benchmark
            </Link>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-raised)]">
            <table className="research-table">
              <thead>
                <tr>
                  <th>Rank</th>
                  <th>Model / Agent Name</th>
                  <th>Resistance Score</th>
                  <th>ASR (Attack Success)</th>
                  <th>Probes Tested</th>
                  <th>Families Covered</th>
                  <th>Memory Res.</th>
                  <th>Planning Res.</th>
                  <th>Tool Res.</th>
                  <th>Last Run</th>
                </tr>
              </thead>
              <tbody>
                {models.map(m => (
                  <tr key={m.agentId} className="hover:bg-[var(--surface-base)] transition-colors">
                    <td className="font-mono text-xs font-bold text-center">
                      <span className={`inline-flex h-6 w-6 items-center justify-center rounded-full text-xs font-bold ${
                        m.rank === 1 ? 'bg-amber-500/20 text-amber-500 border border-amber-500/40' : 'bg-[var(--surface-base)] text-[var(--text-secondary)]'
                      }`}>
                        #{m.rank}
                      </span>
                    </td>
                    <td className="font-bold text-xs text-[var(--text-primary)]">{m.modelName}</td>
                    <td className="font-mono text-xs font-extrabold text-emerald-600 dark:text-emerald-400">{m.overallScore}%</td>
                    <td className="font-mono text-xs font-bold text-rose-600 dark:text-rose-400">{m.asr}%</td>
                    <td className="font-mono text-xs text-center">{m.probesResisted} / {m.probesEvaluated}</td>
                    <td className="font-mono text-xs text-center">
                      {m.familiesCovered} / 8
                      {m.partial && <span className="ml-1.5 badge-semantic badge-warning">Partial</span>}
                    </td>
                    <td className="font-mono text-xs text-center">{pct(m.memoryResistance)}</td>
                    <td className="font-mono text-xs text-center">{pct(m.planningResistance)}</td>
                    <td className="font-mono text-xs text-center font-semibold text-emerald-500">{pct(m.toolResistance)}</td>
                    <td className="font-mono text-xs text-[var(--text-secondary)]">
                      {m.lastEvaluated ? new Date(m.lastEvaluated).toISOString().split('T')[0] : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {untested.length > 0 && (
          <p className="text-[11px] text-[var(--text-muted)] flex items-center gap-1.5">
            <Info className="h-3.5 w-3.5" />
            Not run yet: {untested.map(u => u.modelName).join(', ')}.{' '}
            <Link href="/benchmark" className="text-[var(--primary)] hover:underline">Run a benchmark</Link> to rank them.
          </p>
        )}
      </div>

      {models.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Radar: resistance per attack family */}
          <div className="research-card space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-[var(--text-primary)] uppercase tracking-wider flex items-center gap-1.5">
                <BarChart2 className="h-4 w-4 text-[var(--primary)]" /> Attack Family Resistance Profile
              </h3>
              <div className="flex items-center gap-1 text-[11px] text-[var(--text-muted)] font-mono">
                <Info className="h-3.5 w-3.5 text-amber-500" /> Top 5 models; untested families omitted
              </div>
            </div>

            <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <RadarChart cx="50%" cy="50%" outerRadius="80%" data={radarData}>
                  <PolarGrid stroke="var(--border-default)" opacity={0.4} />
                  <PolarAngleAxis dataKey="family" tick={{ fill: 'var(--text-secondary)', fontSize: 10 }} />
                  <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: 'var(--text-muted)', fontSize: 9 }} />
                  {radarModels.map((m, idx) => (
                    <Radar
                      key={m.agentId}
                      name={m.modelName}
                      dataKey={m.modelName}
                      stroke={colors[idx % colors.length]}
                      fill={colors[idx % colors.length]}
                      fillOpacity={0.15}
                      connectNulls
                    />
                  ))}
                  <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} />
                  <Tooltip contentStyle={{ backgroundColor: 'var(--surface-overlay)', borderColor: 'var(--border-default)', fontSize: '11px' }} />
                </RadarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Outcome distribution: resisted vs compromised */}
          <div className="research-card space-y-3">
            <h3 className="text-sm font-bold text-[var(--text-primary)] uppercase tracking-wider flex items-center gap-1.5">
              <TrendingUp className="h-4 w-4 text-emerald-500" /> Outcome Distribution Matrix
            </h3>
            <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={outcomeData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" />
                  <XAxis dataKey="name" tick={{ fill: 'var(--text-secondary)', fontSize: 10 }} />
                  <YAxis tick={{ fill: 'var(--text-secondary)', fontSize: 10 }} domain={[0, 100]} ticks={[0, 25, 50, 75, 100]} allowDataOverflow unit="%" />
                  <Tooltip contentStyle={{ backgroundColor: 'var(--surface-overlay)', borderColor: 'var(--border-default)', fontSize: '11px' }} />
                  <Legend wrapperStyle={{ fontSize: '11px' }} />
                  <Bar dataKey="Resisted" stackId="a" fill="#10b981" />
                  <Bar dataKey="Compromised" stackId="a" fill="#f43f5e" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
