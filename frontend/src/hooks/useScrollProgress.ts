import { useEffect } from "react";
import { progressFromScroll } from "../lib/storyTimeline";
import { useStory } from "../state/story";

/** The only scroll listener for the story: rAF-throttled, passive, removed on unmount. */
export function useScrollProgress(enabled = true): void {
  useEffect(() => {
    if (!enabled) return;
    let raf = 0;
    const update = () => {
      raf = 0;
      const el = document.documentElement;
      useStory.getState().setProgress(progressFromScroll(window.scrollY, window.innerHeight, el.scrollHeight));
    };
    const on = () => { if (!raf) raf = requestAnimationFrame(update); };
    update();
    window.addEventListener("scroll", on, { passive: true });
    window.addEventListener("resize", on);
    return () => { window.removeEventListener("scroll", on); window.removeEventListener("resize", on); if (raf) cancelAnimationFrame(raf); };
  }, [enabled]);
}
