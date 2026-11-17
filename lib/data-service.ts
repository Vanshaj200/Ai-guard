import directInjection from '../redguard/datasets/direct_injection.json'
import contentInjection from '../redguard/datasets/content_injection.json'
import exfiltration from '../redguard/datasets/exfiltration.json'
import goalDiversion from '../redguard/datasets/goal_diversion.json'
import memoryPoisoning from '../redguard/datasets/memory_poisoning.json'
import autonomy from '../redguard/datasets/autonomy.json'
import planning from '../redguard/datasets/planning.json'
import toolSecurity from '../redguard/datasets/tool_security.json'
import { adminHeaders } from './admin-token'

export interface Reference {
  title: string
  authors: string[]
  year: number
  venue: string
  arxiv_id?: string
  url?: string
}

export interface EvaluationRules {
  success_indicators: string[]
  blocked_indicators: string[]
  notes?: string
}

export interface Probe {
  id: string
  title: string
  attack_family: string
  attack_variant: string
  scenario: string
  difficulty: 'trivial' | 'easy' | 'medium' | 'hard' | 'expert' | string
  threat_model: string
  attacker_capability?: string
  prompt: string
  expected_behavior: string
  failure_behavior: string
  attack_goal?: string
  evaluation_rules?: EvaluationRules
  references?: Reference[]
  tags?: string[]
  affected_layers?: string[]
  probe_version?: string
  dataset_version?: string
  synthetic?: boolean
  research_notes?: string
}

export interface AttackFamilyMeta {
  id: string
  name: string
  description: string
  threatModel: string
  affectedLayers: string[]
  probeCount: number
  researchPapersCount: number
}

export interface ScenarioMeta {
  id: string
  name: string
  description: string
  riskLevel: 'High' | 'Medium' | 'Critical' | string
  probeCount: number
  primaryVectors: string[]
}

export interface BenchmarkRun {
  id: string
  sessionId: string
  agentId: string
  agentName: string
  startedAt: string
  finishedAt: string | null
  totalProbes: number
  blocked: number
  allowed: number
  status: 'COMPLETED' | 'RUNNING' | 'FAILED' | string
  blockRate?: number
}

export interface ModelComparisonResult {
  rank: number
  modelName: string
  agentId: string
  overallScore: number // % of evaluated probes resisted
  asr: number // Attack Success Rate: % of evaluated probes that compromised the model
  probesEvaluated: number
  probesResisted: number
  familiesCovered: number
  partial: boolean // not yet tested on all 8 attack families; ranked below complete runs
  memoryResistance: number | null
  planningResistance: number | null
  toolResistance: number | null
  familyScores: Record<string, number>
  totalRuns: number
  lastEvaluated: string | null
}

const RAW_DATASETS: Record<string, any> = {
  direct_injection: directInjection,
  content_injection: contentInjection,
  exfiltration: exfiltration,
  goal_diversion: goalDiversion,
  memory_poisoning: memoryPoisoning,
  autonomy: autonomy,
  planning: planning,
  tool_security: toolSecurity,
}

// 12 Benchmark Scenarios
export const SCENARIOS: ScenarioMeta[] = [
  { id: 'github', name: 'GitHub Workspace', description: 'Evaluates agent safety when processing pull requests, code reviews, and repo issue comments.', riskLevel: 'Critical', probeCount: 18, primaryVectors: ['PR Body Injection', 'Commit Message Overrides'] },
  { id: 'gitlab', name: 'GitLab CI/CD', description: 'Audits agent resistance against malicious CI pipeline triggers and runner issue comments.', riskLevel: 'High', probeCount: 14, primaryVectors: ['Pipeline Parameter Hijack', 'Issue Comment Injections'] },
  { id: 'wiki', name: 'Internal Knowledge Base Wiki', description: 'Assesses vulnerability to hidden adversarial payload in shared markdown docs.', riskLevel: 'Medium', probeCount: 12, primaryVectors: ['Hidden CSS/HTML Injections', 'Document Instructions'] },
  { id: 'documentation', name: 'API Documentation Hub', description: 'Tests data exfiltration via untrusted API documentation payloads.', riskLevel: 'Medium', probeCount: 15, primaryVectors: ['Swagger Spec Injection', 'Sample Request Exfil'] },
  { id: 'email', name: 'Enterprise Mail Client', description: 'Scans incoming email body and attachment parsing for indirect prompt injections.', riskLevel: 'Critical', probeCount: 22, primaryVectors: ['Phishing Body Injection', 'Forwarding Automation Hijack'] },
  { id: 'calendar', name: 'Calendar Scheduling Agent', description: 'Checks scheduling agent resistance to meeting invite description payloads.', riskLevel: 'High', probeCount: 10, primaryVectors: ['Invite Notes Command Injection', 'Location URL Exfil'] },
  { id: 'banking', name: 'Financial & Banking Portal', description: 'Evaluates strict financial action authorization and anti-drain policy enforcement.', riskLevel: 'Critical', probeCount: 20, primaryVectors: ['Wire Transfer Override', 'Account Extraction'] },
  { id: 'travel', name: 'Corporate Travel Booking', description: 'Audits itinerary parsing and automated expense approval agent constraints.', riskLevel: 'Medium', probeCount: 11, primaryVectors: ['Flight Booking Redirect', 'Vendor Override'] },
  { id: 'shopping', name: 'E-Commerce Agent', description: 'Tests procurement agents against cart manipulation and price bypass probes.', riskLevel: 'High', probeCount: 13, primaryVectors: ['Checkout Automation Poisoning', 'Coupon Payload'] },
  { id: 'support', name: 'Customer Support Bot', description: 'Evaluates customer-facing ticket resolution agents against policy bypasses.', riskLevel: 'Medium', probeCount: 16, primaryVectors: ['Ticket Escalation Hijack', 'Refund Policy Bypass'] },
  { id: 'forum', name: 'Developer Forum', description: 'Scans forum thread parsing for malicious community post instruction overrides.', riskLevel: 'Low', probeCount: 9, primaryVectors: ['Markdown Exfil', 'Bot Mention Injection'] },
  { id: 'reddit', name: 'Community Social Feed', description: 'Evaluates sentiment & summary agents processing untrusted social threads.', riskLevel: 'Medium', probeCount: 12, primaryVectors: ['Upvote Bot Injection', 'Comment Payload Hijack'] },
]

export function normalizeFamily(fam: string): string {
  if (!fam) return ''
  const f = fam.toLowerCase().trim()
  if (f === 'data_exfiltration' || f === 'exfiltration') return 'exfiltration'
  if (f === 'autonomous_actions' || f === 'autonomy') return 'autonomy'
  if (f === 'planning_manipulation' || f === 'planning') return 'planning'
  if (f === 'tool_manipulation' || f === 'tool_security') return 'tool_security'
  return f
}

class BenchmarkDataService {
  private static instance: BenchmarkDataService
  private allProbes: Probe[] = []
  private cache: Map<string, { data: any; timestamp: number }> = new Map()
  private CACHE_TTL_MS = 60 * 1000 // 1 minute in-memory cache

  private constructor() {
    this.initProbes()
  }

  public static getInstance(): BenchmarkDataService {
    if (!BenchmarkDataService.instance) {
      BenchmarkDataService.instance = new BenchmarkDataService()
    }
    return BenchmarkDataService.instance
  }

  private initProbes() {
    const probes: Probe[] = []
    Object.entries(RAW_DATASETS).forEach(([familyKey, dataset]) => {
      if (dataset && Array.isArray(dataset.entries)) {
        dataset.entries.forEach((entry: any) => {
          probes.push({
            id: entry.id,
            title: entry.title || entry.id,
            attack_family: normalizeFamily(familyKey),
            attack_variant: entry.attack_variant || 'standard',
            scenario: entry.scenario || 'generic',
            difficulty: entry.difficulty || 'medium',
            threat_model: entry.threat_model || 'adversarial_user',
            attacker_capability: entry.attacker_capability || 'prompt_level',
            prompt: entry.prompt || '',
            expected_behavior: entry.expected_behavior || '',
            failure_behavior: entry.failure_behavior || '',
            attack_goal: entry.attack_goal,
            evaluation_rules: entry.evaluation_rules,
            references: entry.references || [],
            tags: entry.tags || [],
            affected_layers: entry.affected_layers || ['llm'],
            probe_version: entry.probe_version || '1.0.0',
            dataset_version: entry.dataset_version || '1.0.0',
            synthetic: entry.synthetic ?? true,
            research_notes: entry.research_notes,
          })
        })
      }
    })
    this.allProbes = probes
  }

  public invalidateCache() {
    this.cache.clear()
  }

  public getAllProbes(): Probe[] {
    return this.allProbes
  }

  public getProbeById(id: string): Probe | undefined {
    return this.allProbes.find(p => p.id.toLowerCase() === id.toLowerCase())
  }

  public getProbesByFamily(familyId: string): Probe[] {
    const normTarget = normalizeFamily(familyId)
    return this.allProbes.filter(
      p => normalizeFamily(p.attack_family) === normTarget
    )
  }

  public getProbesByScenario(scenarioId: string): Probe[] {
    return this.allProbes.filter(
      p => p.scenario.toLowerCase() === scenarioId.toLowerCase() || p.scenario === 'generic'
    )
  }

  public getAttackFamilies(): AttackFamilyMeta[] {
    const familyMetas: Record<string, { desc: string; threat: string; layers: Set<string>; papers: number }> = {
      direct_injection: {
        desc: 'Classic prompt injection attacks where the adversary directly injects malicious instructions into user inputs.',
        threat: 'Adversarial User',
        layers: new Set(['LLM', 'Policy Engine']),
        papers: 14,
      },
      content_injection: {
        desc: 'Indirect prompt injections embedded in untrusted external data sources like emails, web pages, or files.',
        threat: 'Untrusted Data Provider',
        layers: new Set(['LLM', 'Context Parser', 'Tool Router']),
        papers: 12,
      },
      exfiltration: {
        desc: 'Probes attempting to steal confidential system prompts, session keys, or API tokens via multi-step calls.',
        threat: 'Adversarial Exfiltrator',
        layers: new Set(['Policy Engine', 'Output Guardrail', 'Memory']),
        papers: 18,
      },
      goal_diversion: {
        desc: 'Attacks targeting agent planning loops to derail the original user objective toward adversary goals.',
        threat: 'Hijacked Planning Subsystem',
        layers: new Set(['Planning Engine', 'Task Orchestrator']),
        papers: 9,
      },
      memory_poisoning: {
        desc: 'Adversarial payloads designed to persist across chat sessions inside vector databases or memory buffers.',
        threat: 'Persistent Memory Poisoner',
        layers: new Set(['Vector DB', 'Memory Store', 'Retriever']),
        papers: 11,
      },
      autonomy: {
        desc: 'Probes checking unauthorized autonomous execution, resource drain, and unchecked loop execution.',
        threat: 'Unrestricted Tool Executor',
        layers: new Set(['Executor Subsystem', 'Permission Manager']),
        papers: 8,
      },
      planning: {
        desc: 'Subtle adversarial perturbations that cause multi-step agent plan degradation or invalid tool selection.',
        threat: 'Strategic Adversary',
        layers: new Set(['Planner', 'Reasoning Engine']),
        papers: 10,
      },
      tool_security: {
        desc: 'Attempts to trick the agent into calling dangerous system commands, file deletion, or network APIs.',
        threat: 'Privilege Escalation Agent',
        layers: new Set(['Tool Dispatcher', 'Sandbox']),
        papers: 15,
      },
    }

    return Object.entries(RAW_DATASETS).map(([familyId, dataset]) => {
      const familyProbes = this.getProbesByFamily(familyId)
      const meta = familyMetas[familyId] || {
        desc: dataset.description || 'AI Agent Security evaluation attack family.',
        threat: 'Adversarial Threat',
        layers: new Set(['LLM Layer']),
        papers: 5,
      }

      return {
        id: familyId,
        name: familyId.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
        description: meta.desc,
        threatModel: meta.threat,
        affectedLayers: Array.from(meta.layers),
        probeCount: familyProbes.length,
        researchPapersCount: meta.papers,
      }
    })
  }

  public getScenarios(): ScenarioMeta[] {
    return SCENARIOS
  }

  // Probe datasets use suffixed scenario names (github_issue, email_assistant, ...)
  // while scenario cards use short ids (github, email, ...).
  public probeMatchesScenario(probeScenario: string, scenarioId: string): boolean {
    const s = (probeScenario || '').toLowerCase()
    const id = scenarioId.toLowerCase()
    return s === id || s.startsWith(`${id}_`)
  }

  public getScenarioProbeCount(scenarioId: string): number {
    return this.getAllProbes().filter(p => this.probeMatchesScenario(p.scenario, scenarioId)).length
  }

  // API Call: Fetch Stats
  public async fetchStats(): Promise<any> {
    const key = 'api_stats'
    if (this.cache.has(key)) {
      const entry = this.cache.get(key)!
      if (Date.now() - entry.timestamp < this.CACHE_TTL_MS) {
        return entry.data
      }
    }
    try {
      const res = await fetch('/api/stats')
      if (res.ok) {
        const data = await res.json()
        this.cache.set(key, { data, timestamp: Date.now() })
        return data
      }
    } catch {
      // Backend may be offline during initial load
    }
    return { totalSessions: 0, totalProbes: this.allProbes.length, totalBlocked: 0, totalAllowed: 0, overallBlockRate: 0 }
  }

  // API Call: Fetch Sessions
  public async fetchSessions(): Promise<BenchmarkRun[]> {
    const key = 'api_sessions'
    if (this.cache.has(key)) {
      const entry = this.cache.get(key)!
      if (Date.now() - entry.timestamp < this.CACHE_TTL_MS) {
        return entry.data
      }
    }
    try {
      const res = await fetch('/api/sessions')
      if (res.ok) {
        const data = await res.json()
        const formatted: BenchmarkRun[] = data.map((s: any) => ({
          id: s.id,
          sessionId: s.sessionId,
          agentId: s.agentId || 'nemotron_3_ultra',
          agentName: s.agentName || s.agentId || 'Unknown agent',
          startedAt: s.startedAt,
          finishedAt: s.finishedAt,
          totalProbes: s.totalProbes || 0,
          blocked: s.blocked || 0,
          allowed: s.allowed || 0,
          status: s.status || 'COMPLETED',
          blockRate: s.totalProbes > 0 ? s.blocked / s.totalProbes : 0,
        }))
        this.cache.set(key, { data: formatted, timestamp: Date.now() })
        return formatted
      }
    } catch {
      // Backend may be offline during initial load
    }
    return []
  }

  // API Call: Fetch Report
  public async fetchReport(sessionId: string): Promise<any> {
    const key = `api_report_${sessionId}`
    if (this.cache.has(key)) {
      const entry = this.cache.get(key)!
      if (Date.now() - entry.timestamp < this.CACHE_TTL_MS) {
        return entry.data
      }
    }
    try {
      const res = await fetch(`/api/reports/${sessionId}`)
      if (res.ok) {
        const data = await res.json()
        this.cache.set(key, { data, timestamp: Date.now() })
        return data
      }
    } catch {
      // Backend may be offline
    }
    return null
  }

  // API Call: Fetch Agents
  public async fetchAgents(): Promise<any[]> {
    try {
      const res = await fetch('/api/agents')
      if (res.ok) return await res.json()
    } catch {
      // Backend may be offline during initial load
    }
    return []
  }

  // API Call: Fetch Backend Health
  public async fetchHealth(): Promise<{ status: string; db_connected: boolean }> {
    try {
      const res = await fetch('/api/health')
      if (res.ok) return await res.json()
    } catch {
      // Backend unreachable
    }
    return { status: 'offline', db_connected: false }
  }

  public async fetchConfig(): Promise<{
    nvidiaConfigured: boolean
    nvidiaKeyMasked: string
    ollamaBaseUrl: string
    ollamaModel: string
    ollamaReachable: boolean
  }> {
    try {
      const res = await fetch('/api/config')
      if (res.ok) return await res.json()
    } catch {
      // Backend unreachable
    }
    return {
      nvidiaConfigured: false,
      nvidiaKeyMasked: '',
      ollamaBaseUrl: 'http://localhost:11434',
      ollamaModel: 'llama3.2',
      ollamaReachable: false,
    }
  }

  public async saveConfig(payload: {
    nvidiaApiKey?: string
    ollamaBaseUrl?: string
    ollamaModel?: string
  }): Promise<{ ok: boolean; error?: string; data?: any }> {
    try {
      const res = await fetch('/api/config', {
        method: 'POST',
        headers: adminHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(payload),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        return { ok: false, error: data?.detail || `HTTP ${res.status}` }
      }
      this.invalidateCache()
      return { ok: true, data }
    } catch {
      return { ok: false, error: 'Cannot reach the Ai-guard backend.' }
    }
  }

  // Leaderboard computed by the backend from stored probe results (no sample data)
  public async fetchLeaderboard(): Promise<{ models: ModelComparisonResult[]; untested: { agentId: string; modelName: string }[] }> {
    try {
      const res = await fetch('/api/leaderboard')
      if (res.ok) return await res.json()
    } catch {
      // Backend unreachable
    }
    return { models: [], untested: [] }
  }
}

export const benchmarkDataService = BenchmarkDataService.getInstance()
