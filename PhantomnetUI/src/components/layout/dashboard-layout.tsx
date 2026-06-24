import { useState, useEffect, useCallback, useRef } from "react"
import { Link, Outlet, useLocation, useNavigate } from "react-router-dom"
import {
  Shield,
  AlertTriangle,
  Zap,
  Activity,
  FileText,
  Settings,
  LayoutDashboard,
  Bell,
  Moon,
  Sun,
  Menu,
  X,
  ShieldAlert,
  CheckCircle,
  Info,
  Trash2,
  User,
  LogOut,
  ShieldCheck,
  UserCheck,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { useTheme } from "@/components/theme-provider"
import { cn } from "@/lib/utils"
import { getSession, clearSession } from "@/App"

// ── Types ─────────────────────────────────────────────────────────────────────

type NotifCategory = "threat" | "scan" | "policy" | "action" | "simulation" | "info"

interface Notification {
  id: string
  category: NotifCategory
  title: string
  detail: string
  timestamp: string
  read: boolean
}

// ── Config ────────────────────────────────────────────────────────────────────

const ARE_URL    = "http://localhost:8000/api/are"
const POLL_MS    = 8_000
const MAX_NOTIFS = 50

// Navigation items — filtered per role in the component
const ALL_NAV = [
  { name: "Overview",          href: "/dashboard",         icon: LayoutDashboard, permKey: "dashboard"       },
  { name: "Threat Detection",  href: "/threat-detection",  icon: Shield,          permKey: "threatDetection"  },
  { name: "Attack Simulation", href: "/attack-simulation", icon: AlertTriangle,   permKey: "attackSimulation" },
  { name: "XAI Engine",        href: "/xai-engine",        icon: Zap,             permKey: "xaiEngine"        },
  { name: "Response Engine",   href: "/response-engine",   icon: Activity,        permKey: "responseEngine"   },
  { name: "Analyst Review",    href: "/analyst-review",    icon: UserCheck,       permKey: "analystReview"    },
  { name: "SIEM Logs",         href: "/siem-logs",         icon: FileText,        permKey: "siemLogs"         },
  { name: "SRC",               href: "/srcCoordination",   icon: ShieldCheck,     permKey: "srcCoordination"  },
  { name: "Settings",          href: "/settings",          icon: Settings,        permKey: "settings"         },
]

// ── Role avatar config ────────────────────────────────────────────────────────

const ROLE_CONFIG = {
  admin:            { label: "Administrator",    initials: (name: string) => name.split(" ").map(w => w[0]).join("").slice(0, 2).toUpperCase(), color: "text-amber-400",  bg: "bg-amber-400/10",  Icon: ShieldCheck },
  security_analyst: { label: "Security Analyst", initials: (name: string) => name.split(" ").map(w => w[0]).join("").slice(0, 2).toUpperCase(), color: "text-emerald-400", bg: "bg-emerald-400/10", Icon: UserCheck   },
  user:             { label: "Standard User",    initials: (name: string) => name.split(" ").map(w => w[0]).join("").slice(0, 2).toUpperCase(), color: "text-blue-400",  bg: "bg-blue-400/10",   Icon: User        },
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function loadNotifs(): Notification[] {
  try {
    const raw = localStorage.getItem("phantomnet_notifications")
    return raw ? JSON.parse(raw) : []
  } catch { return [] }
}

function saveNotifs(notifs: Notification[]) {
  localStorage.setItem("phantomnet_notifications", JSON.stringify(notifs.slice(0, MAX_NOTIFS)))
}

function makeId() {
  return Math.random().toString(36).slice(2, 10)
}

function formatAge(iso: string) {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 60)    return `${diff}s ago`
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return new Date(iso).toLocaleDateString()
}

function CategoryIcon({ category }: { category: NotifCategory }) {
  switch (category) {
    case "threat":     return <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
    case "scan":       return <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
    case "policy":     return <Shield      className="w-4 h-4 text-blue-400 shrink-0" />
    case "action":     return <Zap         className="w-4 h-4 text-purple-400 shrink-0" />
    case "simulation": return <Activity    className="w-4 h-4 text-yellow-400 shrink-0" />
    default:           return <Info        className="w-4 h-4 text-slate-400 shrink-0" />
  }
}

// ── Component ─────────────────────────────────────────────────────────────────

export function DashboardLayout() {
  const [sidebarOpen, setSidebarOpen]   = useState(false)
  // Load existing notifs as already read — only new ones after startup show the badge
  const [notifs, setNotifs]             = useState<Notification[]>(() => loadNotifs().map(n => ({ ...n, read: true })))
  const [dropdownOpen, setDropdownOpen] = useState(false)
  const location   = useLocation()
  const navigate   = useNavigate()
  const { theme, setTheme } = useTheme()

  // ── Session ───────────────────────────────────────────────────────────────
  const session     = getSession()
  const role        = session?.role ?? "user"
  const displayName = session?.displayName ?? "User"
  const email       = session?.email ?? ""
  const permissions = session?.permissions
  const roleConf    = ROLE_CONFIG[role] ?? ROLE_CONFIG.user
  const initials    = roleConf.initials(displayName)

  // Filter nav items based on this session's permissions
  const navigation = ALL_NAV.filter(item =>
    permissions ? permissions[item.permKey as keyof typeof permissions] : true
  )

  // ── Logout ────────────────────────────────────────────────────────────────
  const handleLogout = () => {
    clearSession()
    navigate("/login", { replace: true })
  }

  // ── Notification polling ──────────────────────────────────────────────────
  const seenScanIds   = useRef<Set<string>>(new Set(
    loadNotifs().filter(n => n.category === "scan" || n.category === "threat").map(n => n.id)
  ))
  const seenActionIds = useRef<Set<string>>(new Set(
    loadNotifs().filter(n => n.category === "action" || n.category === "policy").map(n => n.id)
  ))
  // True after the first poll cycle — existing data is seeded silently, no badge bump
  const firstPollDone = useRef(false)

  useEffect(() => { saveNotifs(notifs) }, [notifs])

  const push = useCallback((incoming: Omit<Notification, "id" | "read">[]) => {
    if (incoming.length === 0) return
    setNotifs(prev => [...incoming.map(n => ({ ...n, id: makeId(), read: false })), ...prev].slice(0, MAX_NOTIFS))
  }, [])

  const pollThreats = useCallback(() => {
    try {
      const raw = localStorage.getItem("phantomnet_all_scans")
      if (!raw) return
      const scans: any[] = JSON.parse(raw)
      const newNotifs: Omit<Notification, "id" | "read">[] = []
      scans.forEach(scan => {
        if (seenScanIds.current.has(scan.id)) return
        seenScanIds.current.add(scan.id)
        if (!firstPollDone.current) return  // first poll: seed IDs silently, no badge
        const isAdversarial = scan.status === "detected"
        newNotifs.push({
          category: isAdversarial ? "threat" : "scan",
          title: isAdversarial ? `Threat detected — ${scan.severity?.toUpperCase()}` : "Scan complete — Clean",
          detail: isAdversarial
            ? `${scan.type} on ${scan.modelTarget} (${(scan.confidence * 100).toFixed(0)}% confidence)`
            : `${scan.id} — no adversarial pattern found`,
          timestamp: typeof scan.timestamp === "string" ? scan.timestamp : new Date(scan.timestamp).toISOString(),
        })
      })
      push(newNotifs)
    } catch { /* localStorage unavailable */ }
  }, [push])

  const pollARE = useCallback(async () => {
    try {
      const res = await fetch(`${ARE_URL}/actions?limit=50`, { signal: AbortSignal.timeout(4000) })
      if (!res.ok) return
      const data = await res.json()
      const actions: any[] = Array.isArray(data) ? data : (data.actions ?? [])
      const newNotifs: Omit<Notification, "id" | "read">[] = []
      actions.forEach(action => {
        if (seenActionIds.current.has(action.id)) return
        seenActionIds.current.add(action.id)
        if (!firstPollDone.current) return  // first poll: seed IDs silently, no badge
        newNotifs.push({
          category: "action",
          title: `ARE action — ${action.action.replace("_", " ")}`,
          detail: `Policy: ${action.policyName} → ${action.target} (${action.result}, ${action.executionTime}ms)`,
          timestamp: action.timestamp,
        })
      })
      push(newNotifs)
    } catch { /* ARE offline */ }
  }, [push])

  const seenPolicyTriggers = useRef<Set<string>>(new Set())
  const firstPolicyLoad    = useRef(true)

  const pollPolicies = useCallback(async () => {
    try {
      const res = await fetch(`${ARE_URL}/policies`, { signal: AbortSignal.timeout(4000) })
      if (!res.ok) return
      const policies: any[] = await res.json()
      const newNotifs: Omit<Notification, "id" | "read">[] = []
      policies.forEach(policy => {
        if (!policy.lastTriggered || policy.triggerCount === 0) return
        const key = `${policy.id}:${policy.triggerCount}`
        if (seenPolicyTriggers.current.has(key)) return
        seenPolicyTriggers.current.add(key)
        if (firstPolicyLoad.current) return
        newNotifs.push({
          category: "policy",
          title: `Policy triggered — ${policy.name}`,
          detail: `Action: ${policy.action} • triggered ${policy.triggerCount} time${policy.triggerCount !== 1 ? "s" : ""} total`,
          timestamp: policy.lastTriggered,
        })
      })
      firstPolicyLoad.current = false
      push(newNotifs)
    } catch { /* ARE offline */ }
  }, [push])

  useEffect(() => {
    const run = () => { pollThreats(); pollARE(); pollPolicies() }
    run()
    // After first run IDs are seeded — subsequent polls fire real notifications only
    setTimeout(() => { firstPollDone.current = true }, 500)
    const timer = setInterval(run, POLL_MS)
    return () => clearInterval(timer)
  }, [pollThreats, pollARE, pollPolicies])

  useEffect(() => {
    const handler = (e: Event) => {
      const detail = (e as CustomEvent).detail
      push([{ category: "simulation", title: "Attack simulation complete", detail: detail?.summary ?? "Simulation finished successfully", timestamp: new Date().toISOString() }])
    }
    window.addEventListener("phantomnet:simulation_complete", handler)
    return () => window.removeEventListener("phantomnet:simulation_complete", handler)
  }, [push])

  const handleDropdownOpen = (open: boolean) => {
    setDropdownOpen(open)
    if (open) setNotifs(prev => prev.map(n => ({ ...n, read: true })))
  }

  const clearAll = (e: React.MouseEvent) => {
    e.stopPropagation()
    setNotifs([])
    seenScanIds.current = new Set()
    seenActionIds.current = new Set()
    seenPolicyTriggers.current = new Set()
    localStorage.removeItem("phantomnet_notifications")
  }

  const unread = notifs.filter(n => !n.read).length
  const toggleTheme  = () => setTheme(theme === "light" ? "dark" : "light")
  const getThemeIcon = () => theme === "light" ? <Moon className="h-5 w-5" /> : <Sun className="h-5 w-5" />

  // ── Sidebar nav shared ────────────────────────────────────────────────────
  const NavLinks = ({ onClickItem }: { onClickItem?: () => void }) => (
    <>
      {navigation.map((item) => {
        const isActive = location.pathname === item.href
        return (
          <Link
            key={item.name}
            to={item.href}
            onClick={onClickItem}
            className={cn(
              "group flex items-center px-2 py-2 text-sm font-medium rounded-md transition-colors",
              isActive
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
            )}
          >
            <item.icon className={cn(
              "mr-3 flex-shrink-0 h-5 w-5",
              isActive ? "text-primary-foreground" : "text-muted-foreground group-hover:text-accent-foreground"
            )} />
            {item.name}
          </Link>
        )
      })}
    </>
  )

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="h-screen flex overflow-hidden bg-background">

      {/* Sidebar — desktop */}
      <aside className="hidden md:flex md:flex-shrink-0">
        <div className="flex flex-col w-64">
          <div className="flex flex-col flex-grow border-r border-border bg-card pt-5 pb-4 overflow-y-auto">
            <div className="flex items-center flex-shrink-0 px-4">
              <div className="flex items-center gap-2">
                <Shield className="h-8 w-8 text-primary" />
                <div className="flex flex-col">
                  <h1 className="text-xl font-bold text-foreground">PhantomNet++</h1>
                  <p className="text-xs text-muted-foreground">AI-Powered Security</p>
                </div>
              </div>
            </div>
            <nav className="mt-8 flex-1 px-2 space-y-1">
              <NavLinks />
            </nav>
          </div>
        </div>
      </aside>

      {/* Sidebar — mobile */}
      <div className={cn(
        "fixed inset-0 flex z-40 md:hidden transition-opacity duration-300",
        sidebarOpen ? "opacity-100" : "opacity-0 pointer-events-none"
      )}>
        <div
          className={cn("fixed inset-0 bg-black/50 transition-opacity duration-300", sidebarOpen ? "opacity-100" : "opacity-0")}
          onClick={() => setSidebarOpen(false)}
        />
        <div className={cn(
          "relative flex-1 flex flex-col max-w-xs w-full bg-card border-r border-border transition-transform duration-300 transform",
          sidebarOpen ? "translate-x-0" : "-translate-x-full"
        )}>
          <div className="absolute top-0 right-0 -mr-12 pt-2">
            <button className="ml-1 flex items-center justify-center h-10 w-10 rounded-full focus:outline-none cursor-pointer" onClick={() => setSidebarOpen(false)}>
              <X className="h-6 w-6 text-foreground" />
            </button>
          </div>
          <div className="flex-1 h-0 pt-5 pb-4 overflow-y-auto">
            <div className="flex-shrink-0 flex items-center px-4">
              <div className="flex items-center gap-2">
                <Shield className="h-8 w-8 text-primary" />
                <div className="flex flex-col">
                  <h1 className="text-xl font-bold text-foreground">PhantomNet++</h1>
                  <p className="text-xs text-muted-foreground">AI-Powered Security</p>
                </div>
              </div>
            </div>
            <nav className="mt-8 px-2 space-y-1">
              <NavLinks onClickItem={() => setSidebarOpen(false)} />
            </nav>
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className="flex flex-col w-0 flex-1 overflow-hidden">

        {/* Header */}
        <header className="relative z-10 flex-shrink-0 flex h-16 bg-card border-b border-border shadow-sm">
          <button
            className="px-4 border-r border-border text-muted-foreground focus:outline-none md:hidden cursor-pointer"
            onClick={() => setSidebarOpen(true)}
          >
            <Menu className="h-6 w-6" />
          </button>

          <div className="flex-1 px-4 flex justify-end items-center">
            {/* Right actions */}
            <div className="flex items-center gap-2">

              {/* Theme toggle */}
              <Button variant="ghost" size="icon" onClick={toggleTheme} className="cursor-pointer">
                {getThemeIcon()}
              </Button>

              {/* Notifications */}
              <DropdownMenu open={dropdownOpen} onOpenChange={handleDropdownOpen}>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon" className="relative cursor-pointer">
                    <Bell className="h-5 w-5" />
                    {unread > 0 && (
                      <span className="absolute top-1 right-1 h-4 w-4 rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center leading-none">
                        {unread > 9 ? "9+" : unread}
                      </span>
                    )}
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-96 max-h-[540px] flex flex-col p-0 overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-3 border-b border-border shrink-0">
                    <span className="font-semibold text-sm text-foreground">
                      Notifications
                      {notifs.length > 0 && <span className="ml-1.5 text-xs font-normal text-muted-foreground">({notifs.length})</span>}
                    </span>
                    {notifs.length > 0 && (
                      <button onClick={clearAll} className="flex items-center gap-1 text-xs text-muted-foreground hover:text-destructive transition-colors cursor-pointer">
                        <Trash2 className="w-3 h-3" /> Clear all
                      </button>
                    )}
                  </div>
                  <div className="overflow-y-auto flex-1">
                    {notifs.length === 0 ? (
                      <div className="flex flex-col items-center justify-center py-12 gap-2 text-muted-foreground">
                        <Bell className="w-8 h-8 opacity-25" />
                        <p className="text-sm">No notifications yet</p>
                        <p className="text-xs opacity-60 text-center px-6">Threat detections, ARE actions, policy triggers and simulations will appear here</p>
                      </div>
                    ) : (
                      notifs.map((n, i) => (
                        <div key={n.id}>
                          <DropdownMenuItem className={cn("flex items-start gap-3 px-4 py-3 cursor-default rounded-none focus:bg-accent", !n.read && "bg-primary/5")}>
                            <div className="mt-0.5"><CategoryIcon category={n.category} /></div>
                            <div className="flex-1 min-w-0 space-y-0.5">
                              <p className={cn("text-sm leading-snug", !n.read ? "font-semibold text-foreground" : "font-medium text-foreground/80")}>{n.title}</p>
                              <p className="text-xs text-muted-foreground leading-snug break-words">{n.detail}</p>
                              <p className="text-[11px] text-muted-foreground/50">{formatAge(n.timestamp)}</p>
                            </div>
                            {!n.read && <span className="w-2 h-2 rounded-full bg-primary shrink-0 mt-1.5" />}
                          </DropdownMenuItem>
                          {i < notifs.length - 1 && <DropdownMenuSeparator className="my-0" />}
                        </div>
                      ))
                    )}
                  </div>
                </DropdownMenuContent>
              </DropdownMenu>

              {/* ── User menu ── */}
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" className="relative h-9 w-9 rounded-full cursor-pointer p-0">
                    <div className={cn("h-9 w-9 rounded-full flex items-center justify-center", roleConf.bg)}>
                      <span className={cn("text-sm font-semibold", roleConf.color)}>{initials}</span>
                    </div>
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-56">
                  {/* Who is logged in */}
                  <DropdownMenuLabel>
                    <div className="flex flex-col space-y-1">
                      <p className="text-sm font-medium leading-none">{displayName}</p>
                      <p className="text-xs text-muted-foreground leading-none">{email}</p>
                      {/* Role badge */}
                      <div className={cn("inline-flex items-center gap-1 mt-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium w-fit", roleConf.bg, roleConf.color)}>
                        <roleConf.Icon className="h-3 w-3" />
                        {roleConf.label}
                      </div>
                    </div>
                  </DropdownMenuLabel>
                  <DropdownMenuSeparator />

                  {/* Profile — goes to /profile page */}
                  <DropdownMenuItem
                    className="cursor-pointer gap-2"
                    onClick={() => navigate("/profile")}
                  >
                    <User className="h-4 w-4" />
                    Profile
                  </DropdownMenuItem>

                  {/* Settings — only visible to admin */}
                  {permissions?.settings && (
                    <DropdownMenuItem
                      className="cursor-pointer gap-2"
                      onClick={() => navigate("/settings")}
                    >
                      <Settings className="h-4 w-4" />
                      Settings
                    </DropdownMenuItem>
                  )}

                  <DropdownMenuSeparator />

                  {/* Logout */}
                  <DropdownMenuItem
                    className="cursor-pointer gap-2 text-destructive focus:text-destructive"
                    onClick={handleLogout}
                  >
                    <LogOut className="h-4 w-4" />
                    Log out
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>

            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 relative overflow-y-auto focus:outline-none">
          <div className="py-6 px-4 sm:px-6 lg:px-8">
            <Outlet />
          </div>
        </main>

      </div>
    </div>
  )
}