import type { Plugin } from "@opencode-ai/plugin"
import { tool } from "@opencode-ai/plugin"
import { readFileSync, readdirSync, existsSync } from "fs"
import { join } from "path"

interface HeartbeatConfig {
  file: string
  interval: number // milliseconds
  prompt: string
  lastRun: number
  source: "global" | "project"
}

/**
 * Parse interval string to milliseconds
 * Supports: 30s, 5m, 5min, 1h, 1hr, 1hour
 */
function parseInterval(intervalStr: string): number {
  const match = intervalStr.match(/^(\d+)(s|sec|m|min|h|hr|hour)?$/i)
  if (!match) return 5 * 60 * 1000 // default 5 minutes

  const value = parseInt(match[1], 10)
  const unit = (match[2] || "m").toLowerCase()

  if (unit.startsWith("s")) return value * 1000
  if (unit.startsWith("h")) return value * 60 * 60 * 1000
  return value * 60 * 1000 // minutes
}

/**
 * Parse YAML frontmatter from markdown content
 * Expected format:
 * ---
 * interval: 5m
 * ---
 * Prompt content here
 */
function parseFrontmatter(content: string): { interval: string; prompt: string } {
  const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/)
  if (!match) return { interval: "5m", prompt: content.trim() }

  const frontmatter = match[1]
  const intervalMatch = frontmatter.match(/interval:\s*(\S+)/)

  return {
    interval: intervalMatch?.[1] || "5m",
    prompt: match[2].trim(),
  }
}

/**
 * Format milliseconds to human-readable string
 */
function formatInterval(ms: number): string {
  if (ms < 60 * 1000) return `${ms / 1000}s`
  if (ms < 60 * 60 * 1000) return `${ms / (60 * 1000)}m`
  return `${ms / (60 * 60 * 1000)}h`
}

/**
 * Load heartbeat configs from a directory
 */
function loadHeartbeatsFromDir(
  dir: string,
  source: "global" | "project"
): HeartbeatConfig[] {
  const configs: HeartbeatConfig[] = []

  if (!existsSync(dir)) return configs

  try {
    const files = readdirSync(dir).filter((f) => f.endsWith(".md"))
    for (const file of files) {
      try {
        const content = readFileSync(join(dir, file), "utf-8")
        const { interval, prompt } = parseFrontmatter(content)

        if (!prompt) continue // Skip empty prompts

        configs.push({
          file,
          interval: parseInterval(interval),
          prompt,
          lastRun: 0,
          source,
        })
      } catch {
        // Skip files that can't be read
      }
    }
  } catch {
    // Directory read failed, return empty
  }

  return configs
}

export const HeartbeatPlugin: Plugin = async ({ client, directory }) => {
  const homeDir = process.env.HOME || process.env.USERPROFILE || "~"
  const globalHeartbeatDir = join(homeDir, ".config/opencode/heartbeat")
  const projectHeartbeatDir = join(directory, ".opencode/heartbeat")

  let heartbeats: HeartbeatConfig[] = []
  let checkTimeoutId: ReturnType<typeof setTimeout> | null = null
  let currentSessionId: string | null = null
  let isIdle = true
  let isExecuting = false
  let isEnabled = false // Disabled by default
  const CHECK_INTERVAL = 10 * 1000 // Check every 10 seconds for faster response

  // Load all heartbeat prompts from both directories
  const loadHeartbeats = async () => {
    heartbeats = [
      ...loadHeartbeatsFromDir(globalHeartbeatDir, "global"),
      ...loadHeartbeatsFromDir(projectHeartbeatDir, "project"),
    ]

    if (heartbeats.length > 0) {
      await client.app.log({
        body: {
          service: "heartbeat",
          level: "info",
          message: `Loaded ${heartbeats.length} heartbeat(s): ${heartbeats
            .map((h) => `${h.file} (${formatInterval(h.interval)})`)
            .join(", ")}`,
        },
      })
    }
  }

  // Start the heartbeat checker
  const startHeartbeat = async () => {
    if (isEnabled) {
      return { success: false, message: "Heartbeat is already running" }
    }

    // If we don't have a session ID, try to get the current sessions
    if (!currentSessionId) {
      try {
        const sessions = await client.session.list()
        if (sessions.data && sessions.data.length > 0) {
          // Get the most recent session
          currentSessionId = sessions.data[0].id
          await client.app.log({
            body: {
              service: "heartbeat",
              level: "info",
              message: `Fetched session ID: ${currentSessionId}`,
            },
          })
        }
      } catch (error) {
        await client.app.log({
          body: {
            service: "heartbeat",
            level: "error",
            message: `Failed to get session: ${error}`,
          },
        })
      }
    }

    if (!currentSessionId) {
      return {
        success: false,
        message: "No active session found. Please try again.",
      }
    }

    await loadHeartbeats()

    if (heartbeats.length === 0) {
      return {
        success: false,
        message: `No heartbeat files found. Add .md files to:\n- ${globalHeartbeatDir}\n- ${projectHeartbeatDir}`,
      }
    }

    isEnabled = true

    // Reset lastRun times so heartbeats don't fire immediately
    const now = Date.now()
    for (const hb of heartbeats) {
      hb.lastRun = now
    }

    // Start the check loop using recursive setTimeout
    await scheduleNextCheck()

    await client.tui.showToast({
      body: {
        message: `Heartbeat started: ${heartbeats.length} prompt(s)`,
        variant: "success",
      },
    })

    const heartbeatList = heartbeats
      .map((h) => `- ${h.file} (every ${formatInterval(h.interval)}, ${h.source})`)
      .join("\n")

    return {
      success: true,
      message: `Heartbeat started with ${heartbeats.length} prompt(s):\n${heartbeatList}`,
    }
  }

  // Stop the heartbeat checker
  const stopHeartbeat = async () => {
    if (!isEnabled) {
      return { success: false, message: "Heartbeat is not running" }
    }

    isEnabled = false
    if (checkTimeoutId) {
      clearTimeout(checkTimeoutId)
      checkTimeoutId = null
    }

    await client.tui.showToast({
      body: {
        message: "Heartbeat stopped",
        variant: "info",
      },
    })

    return { success: true, message: "Heartbeat stopped" }
  }

  // Get heartbeat status
  const getStatus = () => {
    if (!isEnabled) {
      return {
        enabled: false,
        message: "Heartbeat is disabled. Use heartbeat_start to enable.",
        heartbeats: [],
      }
    }

    const now = Date.now()
    const status = heartbeats.map((hb) => ({
      file: hb.file,
      interval: formatInterval(hb.interval),
      source: hb.source,
      nextRun: formatInterval(Math.max(0, hb.interval - (now - hb.lastRun))),
    }))

    return {
      enabled: true,
      message: `Heartbeat is running with ${heartbeats.length} prompt(s)`,
      heartbeats: status,
    }
  }

  // Schedule the next heartbeat check using recursive setTimeout
  const scheduleNextCheck = async () => {
    if (!isEnabled) return
    
    await client.app.log({
      body: {
        service: "heartbeat",
        level: "info",
        message: `Scheduling next check in ${CHECK_INTERVAL / 1000}s`,
      },
    })
    
    checkTimeoutId = setTimeout(async () => {
      try {
        await checkHeartbeats()
      } catch (error) {
        await client.app.log({
          body: {
            service: "heartbeat",
            level: "error",
            message: `Check failed: ${error}`,
          },
        })
      }
      scheduleNextCheck() // Schedule next check after this one completes
    }, CHECK_INTERVAL)
  }

  // Check and execute any due heartbeats
  const checkHeartbeats = async () => {
    // Log that we're checking (INFO level so it shows up)
    await client.app.log({
      body: {
        service: "heartbeat",
        level: "info",
        message: `Checking: sessionId=${currentSessionId}, isExecuting=${isExecuting}, isEnabled=${isEnabled}`,
      },
    })

    // Removed idle check - fire regardless of session state
    if (!currentSessionId || isExecuting || !isEnabled) return
    if (heartbeats.length === 0) return

    const now = Date.now()

    // Find all due heartbeats
    const dueHeartbeats = heartbeats.filter((hb) => now - hb.lastRun >= hb.interval)

    await client.app.log({
      body: {
        service: "heartbeat",
        level: "info",
        message: `Due heartbeats: ${dueHeartbeats.length}`,
      },
    })

    if (dueHeartbeats.length === 0) return

    isExecuting = true

    try {
      // Execute sequentially
      for (const hb of dueHeartbeats) {
        // Check if still enabled before each execution
        if (!currentSessionId || !isEnabled) break

        hb.lastRun = Date.now()

        // Show toast notification
        await client.tui.showToast({
          body: {
            message: `Heartbeat: ${hb.file.replace(".md", "")}`,
            variant: "info",
          },
        })

        await client.app.log({
          body: {
            service: "heartbeat",
            level: "info",
            message: `Executing heartbeat: ${hb.file}`,
          },
        })

        // Send the prompt
        await client.session.prompt({
          path: { id: currentSessionId },
          body: {
            parts: [{ type: "text", text: hb.prompt }],
          },
        })

        // Only run one heartbeat per check cycle
        break
      }
    } catch (error) {
      await client.app.log({
        body: {
          service: "heartbeat",
          level: "error",
          message: `Heartbeat execution failed: ${error}`,
        },
      })
    } finally {
      isExecuting = false
    }
  }

  // Cleanup function
  const cleanup = () => {
    if (checkTimeoutId) {
      clearTimeout(checkTimeoutId)
      checkTimeoutId = null
    }
    isEnabled = false
    currentSessionId = null
    heartbeats = []
  }

  return {
    // Custom tools for controlling the heartbeat
    tool: {
      heartbeat_start: tool({
        description:
          "Start the heartbeat system. This will periodically execute prompts from heartbeat files at their configured intervals. Heartbeats only run when the session is idle.",
        args: {},
        async execute() {
          const result = await startHeartbeat()
          return result.message
        },
      }),

      heartbeat_stop: tool({
        description: "Stop the heartbeat system. No more periodic prompts will be executed until started again.",
        args: {},
        async execute() {
          const result = await stopHeartbeat()
          return result.message
        },
      }),

      heartbeat_status: tool({
        description:
          "Check the current status of the heartbeat system, including which prompts are loaded and when they will next run.",
        args: {},
        async execute() {
          const status = getStatus()
          if (!status.enabled) {
            return status.message
          }

          const lines = [status.message, ""]
          for (const hb of status.heartbeats) {
            lines.push(`- ${hb.file}: every ${hb.interval} (${hb.source}), next in ${hb.nextRun}`)
          }
          return lines.join("\n")
        },
      }),
    },

    event: async ({ event }) => {
      // Session created - track the session but don't auto-start
      if (event.type === "session.created") {
        // The session object is in event.properties.info (not .session)
        currentSessionId = event.properties.info?.id || event.properties.session?.id
        isIdle = true
        
        await client.app.log({
          body: {
            service: "heartbeat",
            level: "info",
            message: `Session created, captured ID: ${currentSessionId}`,
          },
        })

        // Pre-load heartbeats to check if any exist
        await loadHeartbeats()

        if (heartbeats.length > 0) {
          await client.app.log({
            body: {
              service: "heartbeat",
              level: "info",
              message: `Heartbeat plugin ready. ${heartbeats.length} prompt(s) available. Use heartbeat_start to enable.`,
            },
          })
        }
      }

      // Session deleted - cleanup
      if (event.type === "session.deleted") {
        cleanup()
      }

      // Track idle state via session.idle event
      if (event.type === "session.idle") {
        isIdle = true
      }

      // Track status changes
      if (event.type === "session.status") {
        const status = event.properties?.status
        // status is an object like { type: "idle" } or { type: "busy" }
        isIdle = status?.type === "idle"
      }
    },
  }
}
