import { Box, Text, useInput } from '@hermes/ink'
import { useRef, useState } from 'react'

import type {
  SubscriptionOverlayState,
  SubscriptionPendingChange,
  SubscriptionResult
} from '../app/interfaces.js'
import type {
  BillingMutationResponse,
  SubscriptionStateResponse,
  SubscriptionTierOption,
  SubscriptionUpgradeResponse
} from '../gatewayTypes.js'
import type { Theme } from '../theme.js'

import { ActionRow, footer, MenuRow, UsageBars } from './overlayPrimitives.js'

interface SubscriptionOverlayProps {
  /** Close the overlay entirely. */
  onClose: () => void
  /** Merge a partial into the overlay state (screen transitions + pending/result). */
  onPatch: (next: Partial<SubscriptionOverlayState>) => void
  overlay: SubscriptionOverlayState
  t: Theme
}

/**
 * The /subscription modal — an in-terminal plan-change flow (V3). A small state
 * machine: overview → picker → confirm → result. Downgrades / cancellations /
 * resume are chargeless; an upgrade charges the card on the subscription via the
 * upgrade RPC, and an SCA/decline is handed off to the portal. Starting a NEW
 * subscription still deep-links to the portal (needs a fresh card — out of scope
 * here). All RPCs live in subscription.ts, reached via `overlay.ctx`.
 */
export function SubscriptionOverlay({ onClose, onPatch, overlay, t }: SubscriptionOverlayProps) {
  const { screen, state: s } = overlay

  // Teams have no personal subscription — dead-end to /topup, no picker.
  if (s.context === 'team') {
    return (
      <Box borderColor={t.color.accent} borderStyle="round" flexDirection="column" paddingX={1}>
        <TeamContextScreen onClose={onClose} s={s} t={t} />
      </Box>
    )
  }

  return (
    <Box borderColor={t.color.accent} borderStyle="round" flexDirection="column" paddingX={1}>
      {screen === 'picker' && <PickerScreen onClose={onClose} onPatch={onPatch} overlay={overlay} t={t} />}
      {screen === 'confirm' && <ConfirmScreen onClose={onClose} onPatch={onPatch} overlay={overlay} t={t} />}
      {screen === 'result' && <ResultScreen onClose={onClose} overlay={overlay} t={t} />}
      {screen === 'overview' && <OverviewScreen onClose={onClose} onPatch={onPatch} overlay={overlay} t={t} />}
    </Box>
  )
}

// ── Shared helpers ───────────────────────────────────────────────────

interface ScreenProps {
  onClose: () => void
  onPatch: (next: Partial<SubscriptionOverlayState>) => void
  overlay: SubscriptionOverlayState
  t: Theme
}

/** A selectable menu row with its action. */
interface Row {
  color?: string
  label: string
  run: () => void
}

/** ↑/↓ + Enter + number-key selection over `rows`; Esc runs `onEscape`. */
function useMenu(rows: Row[], onEscape: () => void): number {
  const [sel, setSel] = useState(0)

  useInput((ch, key) => {
    if (key.escape) {
      return onEscape()
    }

    if (key.upArrow && sel > 0) {
      setSel(v => v - 1)
    }

    if (key.downArrow && sel < rows.length - 1) {
      setSel(v => v + 1)
    }

    if (key.return) {
      return rows[sel]?.run()
    }

    const n = parseInt(ch, 10)

    if (n >= 1 && n <= rows.length) {
      return rows[n - 1]?.run()
    }
  })

  return Math.min(sel, Math.max(0, rows.length - 1))
}

/** ISO datetime → YYYY-MM-DD for display, or a soft fallback. */
function shortDate(iso?: null | string): string {
  return iso && iso.length >= 10 ? iso.slice(0, 10) : 'the end of the billing period'
}

/** Integer cents → "$X.YY", or null when no amount is quoted. */
function centsDisplay(cents?: null | number): null | string {
  return typeof cents === 'number' ? `$${(cents / 100).toFixed(2)}` : null
}

/**
 * Map a failed RPC envelope to a result. insufficient_scope is special-cased:
 * /subscription has no in-terminal step-up (that lives on /topup), so route the
 * user there to enable terminal billing, then retry.
 */
function errorResult(r: { error?: string; message?: string; portal_url?: null | string } | null): SubscriptionResult {
  if (r?.error === 'insufficient_scope') {
    return {
      message: 'Terminal billing is not enabled for this account. Run /topup to enable it, then try again.',
      ok: false,
      recoveryUrl: r.portal_url ?? null
    }
  }

  return {
    message: r?.message || r?.error || 'Something went wrong. Try again, or manage on the portal.',
    ok: false,
    recoveryUrl: r?.portal_url ?? null
  }
}

/** Map a chargeless pending-change mutation (schedule / cancel / resume). */
function mutationResult(r: BillingMutationResponse | null, okMessage: string): SubscriptionResult {
  return r?.ok ? { message: r.message || okMessage, ok: true } : errorResult(r)
}

/** Map an upgrade response, routing SCA / decline to a portal recovery. */
function upgradeResult(r: null | SubscriptionUpgradeResponse): SubscriptionResult {
  if (!r) {
    return { message: 'The upgrade could not be completed.', ok: false }
  }

  if (r.ok && (r.status === 'already_on_tier' || r.status === 'upgraded')) {
    return {
      message:
        r.status === 'already_on_tier'
          ? `You are already on ${r.target_tier_name ?? 'this plan'}.`
          : `Upgraded to ${r.target_tier_name ?? 'your new plan'}. Your new monthly credits land in a moment.`,
      ok: true
    }
  }

  if (r.status === 'requires_action') {
    return {
      message: 'This upgrade needs extra verification (3DS). Finish it on the portal.',
      ok: false,
      recoveryUrl: r.recovery_url ?? null
    }
  }

  if (r.status === 'payment_failed') {
    return {
      message: 'Your card was declined. Update your payment method on the portal and try again.',
      ok: false,
      recoveryUrl: r.recovery_url ?? null
    }
  }

  return errorResult(r)
}

// ── Screen: Overview (plan + usage + entry to the change flow) ────────

/** Status line — dollars-only, state-matched (the bar carries the breakdown). */
function statusLine(s: SubscriptionStateResponse): string {
  const u = s.usage
  const plan = s.current?.tier_name ?? u?.plan_name ?? null
  const renewsRaw = u?.renews_display ?? null
  const renews = renewsRaw ? ` · renews ${renewsRaw}` : ''
  const viewOnly = !s.can_change_plan

  if (!plan) {
    return 'Plan: Free · free models only'
  }

  if (u?.status === 'low' && u.total_spendable_display) {
    return `Plan: ${plan} · ${u.total_spendable_display} left`
  }

  const left = u?.total_spendable_display ? ` · ${u.total_spendable_display} left` : ''

  return `Plan: ${plan}${left}${viewOnly ? ' · view only' : renews}`
}

function OverviewScreen({ onClose, onPatch, overlay, t }: ScreenProps) {
  const { ctx, state: s } = overlay
  const c = s.current
  const isFree = !c?.tier_id
  const isCancelScheduled = !!c?.cancel_at_period_end
  const hasPendingDowngrade = !!c?.pending_downgrade_tier_name
  const hasPendingChange = isCancelScheduled || hasPendingDowngrade
  // Admin/owner on a personal paid plan can change it in-terminal; otherwise the
  // portal enforces who can act (members) / starting a new sub needs a card.
  const canChange = s.can_change_plan && !isFree

  // Guard the async resume so a double-press cannot fire two DELETEs mid-await.
  const busyRef = useRef(false)

  const cancelOn = c?.cancellation_effective_display ?? c?.cancellation_effective_at

  const cancellationNote = isCancelScheduled
    ? cancelOn
      ? `Cancels on ${cancelOn} — your plan stays active until then.`
      : 'Cancellation scheduled — your plan stays active until the end of the billing period.'
    : null

  const downgradeOn = c?.pending_downgrade_display ?? c?.pending_downgrade_at ?? 'the end of the billing period'

  const downgradeNote =
    !isCancelScheduled && hasPendingDowngrade
      ? `Scheduled to switch to ${c?.pending_downgrade_tier_name} on ${downgradeOn}.`
      : null

  const u = s.usage
  const freeNudge = isFree ? 'Paid models need a subscription. Start one to reach them.' : null

  const lowNudge =
    u?.status === 'low'
      ? `Low balance · ${u.total_spendable_display ?? 'under $5'} left. Top up or upgrade before a mid-run cutoff.`
      : null

  const doManage = () => {
    if (s.portal_url) {
      void ctx.openManageLink()
    } else {
      ctx.sys('🔴 No portal URL available — manage your subscription on the Nous portal.')
    }

    return onClose()
  }

  const doResume = () => {
    if (busyRef.current) {
      return
    }

    busyRef.current = true
    void ctx
      .resume()
      .then(r => onPatch({ result: mutationResult(r, 'Your pending change was undone — you stay on your current plan.'), screen: 'result' }))
  }

  const rows: Row[] = []

  if (canChange) {
    rows.push({ label: 'Change plan', run: () => onPatch({ pending: null, screen: 'picker' }) })

    if (hasPendingChange) {
      rows.push({ color: t.color.ok, label: 'Keep current plan (undo pending change)', run: doResume })
    } else {
      rows.push({
        label: 'Cancel subscription',
        run: () => onPatch({ pending: { kind: 'cancellation', preview: null, targetTierId: null }, screen: 'confirm' })
      })
    }
  }

  rows.push({ label: isFree ? 'Start a subscription' : 'Manage on portal', run: doManage })
  rows.push({ label: 'Close', run: onClose })

  const sel = useMenu(rows, onClose)

  return (
    <Box flexDirection="column">
      <Text bold color={t.color.accent}>
        {statusLine(s)}
      </Text>
      <UsageBars model={s.usage} t={t} />
      {freeNudge && (
        <Box marginTop={1}>
          <Text color={t.color.warn}>
            {'> '}
            {freeNudge}
          </Text>
        </Box>
      )}
      {lowNudge && (
        <Box marginTop={1}>
          <Text color={t.color.warn}>
            {'! '}
            {lowNudge}
          </Text>
        </Box>
      )}
      {s.org_name && (
        <Text color={t.color.muted}>
          Org: {s.org_name}
          {s.role ? ` · ${s.role}` : ''}
        </Text>
      )}
      {cancellationNote && (
        <Box marginTop={1}>
          <Text color={t.color.warn}>{cancellationNote}</Text>
        </Box>
      )}
      {downgradeNote && (
        <Box marginTop={1}>
          <Text color={t.color.warn}>{downgradeNote}</Text>
        </Box>
      )}

      <Text />
      {rows.map((row, i) => (
        <MenuRow active={sel === i} index={i + 1} key={row.label} label={row.label} t={t} />
      ))}

      <Text />
      {footer('↑/↓ select · Enter confirm · Esc close', t)}
    </Box>
  )
}

// ── Screen: Picker (choose a tier → preview → confirm) ───────────────

function PickerScreen({ onClose, onPatch, overlay, t }: ScreenProps) {
  const { ctx, state: s } = overlay
  const currentOrder = s.tiers.find(tier => tier.is_current)?.tier_order ?? 0

  // Selectable = enabled, not the current plan, and not the free/no-sub tier
  // (going to free is a cancellation, offered on the overview). Sorted by price.
  const choices: SubscriptionTierOption[] = s.tiers
    .filter(tier => tier.is_enabled && !tier.is_current && tier.tier_order > 0)
    .sort((a, b) => a.tier_order - b.tier_order)

  // Guard the async preview so a double-press cannot fire two quotes.
  const busyRef = useRef(false)

  const pick = (tier: SubscriptionTierOption) => {
    if (busyRef.current) {
      return
    }

    busyRef.current = true
    void ctx.preview(tier.tier_id).then(p => {
      if (!p) {
        return onPatch({ result: { message: 'Could not preview that change.', ok: false }, screen: 'result' })
      }

      if (!p.ok) {
        return onPatch({ result: errorResult(p), screen: 'result' })
      }

      // charge_now ⇒ an upgrade (charges now); everything else schedules at
      // period end. blocked/no_op still go to confirm, which shows why + no apply.
      const kind = p.effect === 'charge_now' ? 'upgrade' : 'tier_change'
      onPatch({ pending: { kind, preview: p, targetTierId: tier.tier_id }, screen: 'confirm' })
    })
  }

  const back = () => onPatch({ screen: 'overview' })

  const rows: Row[] = choices.map(tier => {
    const direction = tier.tier_order > currentOrder ? 'upgrade' : 'downgrade'

    return {
      label: `${tier.name} · ${tier.dollars_per_month_display}/mo · ${direction}`,
      run: () => pick(tier)
    }
  })

  rows.push({ label: 'Back', run: back })

  const sel = useMenu(rows, back)

  return (
    <Box flexDirection="column">
      <Text bold color={t.color.accent}>
        Change plan
      </Text>
      <Text color={t.color.muted}>
        Current: {s.current?.tier_name ?? 'Free'}. Pick a plan to see the effect before confirming.
      </Text>
      <Text />
      {choices.length === 0 && <Text color={t.color.muted}>No other plans are available to switch to right now.</Text>}
      {rows.map((row, i) => (
        <MenuRow active={sel === i} index={i + 1} key={row.label} label={row.label} t={t} />
      ))}
      <Text />
      {footer('↑/↓ select · Enter preview · Esc back', t)}
    </Box>
  )
}

// ── Screen: Confirm (show the previewed effect, then apply) ──────────

function ConfirmScreen({ onClose, onPatch, overlay, t }: ScreenProps) {
  const { ctx, state: s } = overlay
  const pending: null | SubscriptionPendingChange = overlay.pending ?? null
  const preview = pending?.preview ?? null
  const isCancellation = pending?.kind === 'cancellation'
  // Cancellation is always a scheduled (chargeless) effect; otherwise trust the
  // quote (default to blocked so a missing quote never offers an apply).
  const effect = isCancellation ? 'scheduled' : (preview?.effect ?? 'blocked')

  const [submitting, setSubmitting] = useState(false)
  // Synchronous guard: two key events can both see submitting===false before
  // React commits, double-firing the mutation/charge.
  const submittingRef = useRef(false)

  const back = () => onPatch({ pending: null, screen: isCancellation ? 'overview' : 'picker' })

  const apply = () => {
    if (submittingRef.current || !pending) {
      return
    }

    submittingRef.current = true
    setSubmitting(true)

    const finish = (result: SubscriptionResult) => onPatch({ result, screen: 'result' })

    if (pending.kind === 'cancellation') {
      void ctx
        .scheduleCancellation()
        .then(r => finish(mutationResult(r, 'Your subscription is scheduled to cancel at the end of the billing period.')))

      return
    }

    if (pending.kind === 'upgrade') {
      void ctx.upgrade(pending.targetTierId ?? '', pending.idempotencyKey).then(r => finish(upgradeResult(r)))

      return
    }

    void ctx
      .scheduleChange(pending.targetTierId ?? '')
      .then(r => finish(mutationResult(r, 'Your plan change is scheduled for the end of the billing period.')))
  }

  const manage = () => {
    void ctx.openManageLink()

    return onClose()
  }

  // Build the rows. blocked/no_op have nothing to apply; blocked offers the
  // portal as the escape hatch.
  const amount = centsDisplay(preview?.amount_due_now_cents)
  const targetName = isCancellation ? null : (preview?.target_tier_name ?? 'the selected plan')

  let primary: null | Row = null

  if (isCancellation) {
    primary = { color: t.color.warn, label: 'Cancel subscription', run: apply }
  } else if (effect === 'charge_now') {
    primary = { color: t.color.ok, label: amount ? `Pay ${amount} & upgrade now` : 'Upgrade now (prorated charge)', run: apply }
  } else if (effect === 'scheduled') {
    primary = { color: t.color.ok, label: `Schedule change to ${targetName}`, run: apply }
  } else if (effect === 'blocked') {
    primary = { label: 'Manage on portal', run: manage }
  }

  const rows: Row[] = primary ? [primary, { label: 'Back', run: back }] : [{ label: 'Back', run: back }]
  const sel = useMenu(rows, back)

  return (
    <Box flexDirection="column">
      <Text bold color={t.color.accent}>
        {isCancellation ? 'Confirm cancellation' : 'Confirm plan change'}
      </Text>
      {submitting && <Text color={t.color.muted}>Working…</Text>}

      {isCancellation && (
        <>
          <Text color={t.color.text}>
            Cancel {s.current?.tier_name ?? 'your plan'} — it stays active until {shortDate(s.current?.cycle_ends_at)}, then
            will not renew.
          </Text>
          <Text color={t.color.muted}>You keep your remaining credits for this period. You can resume before it ends.</Text>
        </>
      )}

      {effect === 'charge_now' && !isCancellation && (
        <>
          <Text color={t.color.text}>
            Upgrade to {targetName}.{' '}
            {amount ? `You will be charged ${amount} now (prorated).` : 'You will be charged the prorated amount now.'}
          </Text>
          {preview?.monthly_credits_delta && (
            <Text color={t.color.muted}>Monthly credits change: {preview.monthly_credits_delta}.</Text>
          )}
          <Text color={t.color.muted}>The card on your subscription will be charged.</Text>
        </>
      )}

      {effect === 'scheduled' && !isCancellation && (
        <>
          <Text color={t.color.text}>
            Change to {targetName} — takes effect {shortDate(preview?.effective_at)}. No charge now; you keep your current
            plan until then.
          </Text>
          {preview?.monthly_credits_delta && (
            <Text color={t.color.muted}>Monthly credits change: {preview.monthly_credits_delta}.</Text>
          )}
        </>
      )}

      {effect === 'no_op' && !isCancellation && (
        <Text color={t.color.muted}>You are already on {targetName} — nothing to change.</Text>
      )}

      {effect === 'blocked' && !isCancellation && (
        <Text color={t.color.warn}>{preview?.reason ?? 'That change cannot be made here — manage it on the portal.'}</Text>
      )}

      <Text />
      {rows.map((row, i) => (
        <ActionRow active={sel === i} color={row.color} key={row.label} label={row.label} t={t} />
      ))}
      <Text />
      {footer('↑/↓ select · Enter confirm · Esc back', t)}
    </Box>
  )
}

// ── Screen: Result (outcome + optional portal recovery) ──────────────

function ResultScreen({ onClose, overlay, t }: Omit<ScreenProps, 'onPatch'>) {
  const { ctx } = overlay
  const result: null | SubscriptionResult = overlay.result ?? null
  const recoveryUrl = result?.recoveryUrl ?? null

  const openRecovery = () => {
    if (recoveryUrl) {
      ctx.openPortal(recoveryUrl)
    }

    return onClose()
  }

  const rows: Row[] = recoveryUrl
    ? [{ color: t.color.accent, label: 'Open the portal to finish', run: openRecovery }, { label: 'Close', run: onClose }]
    : [{ label: 'Close', run: onClose }]

  const sel = useMenu(rows, onClose)

  return (
    <Box flexDirection="column">
      <Text bold color={result?.ok ? t.color.ok : t.color.warn}>
        {result?.ok ? 'Done' : 'Could not complete'}
      </Text>
      <Text color={t.color.text}>{result?.message ?? ''}</Text>
      {result?.ok && <Text color={t.color.muted}>Re-run /subscription to see the updated plan.</Text>}
      <Text />
      {rows.map((row, i) => (
        <ActionRow active={sel === i} color={row.color} key={row.label} label={row.label} t={t} />
      ))}
      <Text />
      {footer('↑/↓ select · Enter · Esc close', t)}
    </Box>
  )
}

// ── Screen: Team context (no tier picker — teams use shared credits) ──

interface TeamContextScreenProps {
  onClose: () => void
  s: SubscriptionStateResponse
  t: Theme
}

function TeamContextScreen({ onClose, s, t }: TeamContextScreenProps) {
  useInput((_ch, key) => {
    if (key.escape || key.return) {
      return onClose()
    }
  })

  return (
    <Box flexDirection="column">
      <Text bold color={t.color.accent}>
        Team subscription
      </Text>
      {s.org_name && (
        <Text color={t.color.muted}>
          Org: {s.org_name}
          {s.role ? ` · ${s.role}` : ''}
        </Text>
      )}
      <Text />
      <Text color={t.color.text}>
        This terminal is connected to {s.org_name ?? 'a team org'}. Teams run on a shared balance · use /topup to add
        funds.
      </Text>
      <Text color={t.color.muted}>Personal subscriptions live on your personal account.</Text>

      <Text />
      {footer('Enter/Esc close', t)}
    </Box>
  )
}
