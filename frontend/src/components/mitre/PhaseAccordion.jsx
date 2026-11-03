import { useRef, useEffect, useState, useCallback } from 'react'
import { gsap } from 'gsap'

import './PhaseAccordion.css'

// The 9 kill-chain phases as an expanding accordion, adapted from the supplied
// AccordionGallery. Nine equal cards in a `lg:grid-cols-9` row left no room for
// anything but a number; here the phase under the pointer takes about half the
// width and the rest fold away at an angle.
//
// The GSAP timeline, the flex-grow maths, the parallax drift, the tilt and the
// label stagger are unchanged. Two things are adapted:
//
//  * there are no photographs. Each panel's "media" is a gradient tinted by the
//    phase's own colour from lib/schema, so the grayscale treatment still means
//    something: inactive phases desaturate, the open one returns to full colour.
//  * the gallery owned its `active` index outright. This page already has a
//    selected phase that filters the explorer below, so hover previews and a
//    click commits — see `active` vs `selectedPhase`.

const clampIndex = (i, count) => Math.min(Math.max(i, 0), Math.max(0, count - 1))

const PhaseAccordion = ({
  phases = [],
  colors = [],
  selectedPhase = 'all',
  onSelectPhase,
  accentColor = '#ffffff',
  overlayColor = '#0b1020',
  textColor = '#ffffff',
  height = 300,
  gap = 8,
  radius = 14,
  expandRatio = 0.4,
  orientation = 'horizontal',
  duration = 0.6,
  ease = 'power3.out',
  parallax = 0.5,
  tilt = 8,
  stagger = 0.06,
  trigger = 'hover',
  grayscale = true,
  className = '',
}) => {
  const rootRef = useRef(null)
  const panelRefs = useRef([])
  const mediaRefs = useRef([])
  const barRefs = useRef([])
  const textRefs = useRef([])
  const tlRef = useRef(null)
  const firstRunRef = useRef(true)
  const mediaSizeRef = useRef(320)

  const vertical = orientation === 'vertical'
  const count = phases.length

  // The selected phase is the resting position; hover moves the open panel
  // without changing what the page below is filtered to.
  const selectedIndex = selectedPhase === 'all' ? -1 : phases.findIndex((p) => String(p.id) === selectedPhase)
  const [active, setActive] = useState(() => (selectedIndex >= 0 ? selectedIndex : 0))

  useEffect(() => {
    if (selectedIndex >= 0) setActive(clampIndex(selectedIndex, count))
  }, [selectedIndex, count])

  const prefersReduced =
    typeof window !== 'undefined' && window.matchMedia
      ? window.matchMedia('(prefers-reduced-motion: reduce)').matches
      : false

  const applyLayout = useCallback(
    (animate) => {
      const panels = panelRefs.current
      if (!panels.length) return

      const r = Math.min(Math.max(expandRatio, 0.2), 0.9)
      const grow = count > 1 ? (r * (count - 1)) / (1 - r) : 1
      const mediaSize = mediaSizeRef.current

      tlRef.current?.kill()
      const dur = animate && !prefersReduced ? duration : 0
      const tl = gsap.timeline()

      panels.forEach((panel, i) => {
        if (!panel) return
        const isActive = i === active
        const media = mediaRefs.current[i]
        const bar = barRefs.current[i]
        const text = textRefs.current[i]

        const rot = isActive ? 0 : i < active ? tilt : -tilt
        const rotProp = vertical ? { rotateX: -rot } : { rotateY: rot }

        tl.to(panel, { flexGrow: isActive ? grow : 1, ...rotProp, duration: dur, ease }, 0)

        if (media) {
          const drift = Math.max(-1.5, Math.min(1.5, active - i))
          const shift = drift * parallax * mediaSize * 0.06
          const gray = grayscale ? (isActive ? 0 : 1) : 0
          tl.to(
            media,
            {
              xPercent: -50,
              yPercent: -50,
              x: vertical ? 0 : isActive ? 0 : shift,
              y: vertical ? (isActive ? 0 : shift) : 0,
              '--ag-gray': gray,
              '--ag-dim': isActive ? 0 : 0.35,
              duration: dur,
              ease,
            },
            0,
          )
        }

        if (bar && text) {
          if (isActive) {
            tl.to([bar, text], { opacity: 1, x: 0, duration: dur, ease, stagger: prefersReduced ? 0 : stagger }, 0)
          } else {
            tl.to([bar, text], { opacity: 0, x: -14, duration: dur * 0.6, ease }, 0)
          }
        }
      })

      tlRef.current = tl
    },
    [active, count, expandRatio, duration, ease, vertical, tilt, parallax, grayscale, stagger, prefersReduced],
  )

  useEffect(() => {
    const el = rootRef.current
    if (!el) return

    const measure = () => {
      const rect = el.getBoundingClientRect()
      const total = vertical ? rect.height : rect.width
      const usable = Math.max(total - gap * (count - 1), 120)
      const size = Math.max(140, usable * Math.min(Math.max(expandRatio, 0.2), 0.9) * 1.22)
      mediaSizeRef.current = size
      el.style.setProperty('--ag-media-size', `${size}px`)
      applyLayout(!firstRunRef.current)
    }

    measure()
    const ro = new ResizeObserver(measure)
    ro.observe(el)
    return () => ro.disconnect()
  }, [applyLayout, gap, count, expandRatio, vertical])

  useEffect(() => {
    applyLayout(!firstRunRef.current)
    firstRunRef.current = false
  }, [applyLayout])

  useEffect(
    () => () => {
      tlRef.current?.kill()
    },
    [],
  )

  const handleEnter = (i) => {
    if (trigger === 'hover') setActive(i)
  }

  // Leaving the strip returns the open panel to whatever is actually selected,
  // so the view never disagrees with the filter below it.
  const handleLeave = () => {
    if (trigger === 'hover' && selectedIndex >= 0) setActive(clampIndex(selectedIndex, count))
  }

  const handleClick = (i) => {
    setActive(i)
    const id = String(phases[i].id)
    onSelectPhase?.(selectedPhase === id ? 'all' : id)
  }

  const handleKeyDown = (i, e) => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
      e.preventDefault()
      setActive((i + 1) % count)
      panelRefs.current[(i + 1) % count]?.focus()
    } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
      e.preventDefault()
      setActive((i - 1 + count) % count)
      panelRefs.current[(i - 1 + count) % count]?.focus()
    } else if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      handleClick(i)
    }
  }

  if (!count) return null

  return (
    <div
      ref={rootRef}
      className={`phase-accordion${vertical ? ' phase-accordion--vertical' : ''}${className ? ` ${className}` : ''}`}
      style={{
        '--ag-accent': accentColor,
        '--ag-overlay': overlayColor,
        '--ag-text': textColor,
        '--ag-gap': `${gap}px`,
        '--ag-radius': `${radius}px`,
        height: vertical ? `${Math.round(height * 1.6)}px` : `${height}px`,
      }}
      onMouseLeave={handleLeave}
      role="list"
      aria-label="Kill-chain phases"
    >
      {phases.map((p, i) => {
        const isActive = i === active
        const isSelected = String(p.id) === selectedPhase
        const color = colors[i] ?? '#64748b'
        return (
          <button
            key={p.id}
            type="button"
            ref={(el) => (panelRefs.current[i] = el)}
            className={`ag-panel${isActive ? ' ag-panel--active' : ''}${isSelected ? ' ag-panel--selected' : ''}`}
            style={{ borderRadius: `${radius}px` }}
            onClick={() => handleClick(i)}
            onMouseEnter={() => handleEnter(i)}
            onFocus={() => setActive(i)}
            onKeyDown={(e) => handleKeyDown(i, e)}
            role="listitem"
            aria-pressed={isSelected}
            aria-label={`Phase ${p.id}, ${p.name}, ${p.count} session${p.count === 1 ? '' : 's'}`}
          >
            <span className="ag-panel__frame">
              {/* Stands in for the gallery's photograph: a gradient in the
                  phase's own colour, so the grayscale pass still reads. */}
              <span
                className="ag-panel__media"
                ref={(el) => (mediaRefs.current[i] = el)}
                style={{
                  background: `linear-gradient(155deg, ${color} 0%, ${color}cc 45%, ${color}66 100%)`,
                }}
              >
                <span className="ag-panel__phase-no">{p.id}</span>
              </span>
              <span className="ag-panel__overlay" aria-hidden="true" />
            </span>

            {/* Always legible, however narrow the panel gets. */}
            <span className="ag-panel__rail" aria-hidden="true">
              <span className="ag-panel__rail-no">P{p.id}</span>
              <span className="ag-panel__rail-count">{p.count}</span>
            </span>

            <span className="ag-panel__label" aria-hidden="true">
              <span className="ag-panel__bar" ref={(el) => (barRefs.current[i] = el)} />
              <span className="ag-panel__text" ref={(el) => (textRefs.current[i] = el)}>
                <span className="ag-panel__title">{p.name}</span>
                <span className="ag-panel__meta">
                  {p.count} session{p.count === 1 ? '' : 's'} · {p.stateCount} micro-states ·{' '}
                  {p.interaction} interaction
                </span>
              </span>
            </span>
          </button>
        )
      })}
    </div>
  )
}

export default PhaseAccordion
