import React from 'react';

export function Icon({ name, size = 20 }) {
  const paths = {
    shield: <><path d="M12 3 3.5 6v6c0 5 8.5 9 8.5 9s8.5-4 8.5-9V6Z"/><path d="m8 12 3 3 5-6"/></>,
    grid: <><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>,
    pulse: <path d="M2 12h5l3-8 4 16 3-8h5"/>,
    code: <><path d="m8 6-6 6 6 6m8-12 6 6-6 6m-3-15-2 18"/></>,
    file: <><path d="M14 2H5v20h14V7Zm0 0v5h5M8 12h8m-8 4h6"/></>,
    play: <path d="m8 4 12 8-12 8Z"/>,
    arrow: <path d="M4 12h16m-6-6 6 6-6 6"/>,
    check: <path d="m5 12 4 4L19 6"/>,
  };
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name] || paths.pulse}</svg>;
}
export function Badge({ children, tone = '' }) { return <span className={`badge ${tone}`}>{children}</span>; }
export function Json({ value }) { return <pre>{JSON.stringify(value, null, 2)}</pre>; }
export function Empty({ title, children, icon = 'pulse' }) {
  return <div className="empty"><span className="empty-icon"><Icon name={icon} size={25}/></span><strong>{title}</strong><p>{children}</p></div>;
}
