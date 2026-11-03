// The page title and subtitle now live in the shell's header bar
// (components/layout/Topbar.jsx), driven by the route — that is how the Pulse
// console is laid out, and it keeps one title per screen. This component is
// what remains: a page's own actions, right-aligned above its content.
//
// `title` and `subtitle` are still accepted so pages did not all need editing,
// but they are intentionally not rendered. Dynamic titles that the route map
// cannot produce belong in the page body.
export default function PageHeader({ actions }) {
  if (!actions) return null
  return <div className="mb-6 flex flex-wrap items-center justify-end gap-2">{actions}</div>
}
