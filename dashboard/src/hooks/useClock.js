import { useEffect, useState } from "react";

/**
 * Ticking UTC clock with ISO + HH:MM:SS slices, refreshed every second.
 * Single interval per consumer; cheap enough to use directly in the header.
 */
export function useClock() {
  const [now, setNow] = useState(() => new Date());

  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  const pad = (n) => String(n).padStart(2, "0");
  const utc = `${now.getUTCFullYear()}-${pad(now.getUTCMonth() + 1)}-${pad(
    now.getUTCDate()
  )}`;
  const time = `${pad(now.getUTCHours())}:${pad(now.getUTCMinutes())}:${pad(
    now.getUTCSeconds()
  )}`;

  return { now, utc, time, label: `${utc} ${time} UTC` };
}
