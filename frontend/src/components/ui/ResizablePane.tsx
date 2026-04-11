"use client";
import React, { useState, useEffect } from "react";

interface ResizablePaneProps {
  children: React.ReactNode;
  initialWidth: number;
  minWidth: number;
  maxWidth: number;
  side: "left" | "right";
  isCollapsed: boolean;
  onWidthChange?: (width: number) => void;
}

export default function ResizablePane({
  children,
  initialWidth,
  minWidth,
  maxWidth,
  side,
  isCollapsed,
  onWidthChange
}: ResizablePaneProps) {
  const [width, setWidth] = useState(initialWidth);
  const [isResizing, setIsResizing] = useState(false);

  useEffect(() => {
    if (!isResizing) return;

    const handlePointerMove = (event: PointerEvent) => {
      let nextWidth;
      if (side === "left") {
        nextWidth = Math.min(maxWidth, Math.max(minWidth, event.clientX));
      } else {
        nextWidth = Math.min(maxWidth, Math.max(minWidth, window.innerWidth - event.clientX));
      }
      setWidth(nextWidth);
      if (onWidthChange) onWidthChange(nextWidth);
    };

    const stopResizing = () => setIsResizing(false);

    window.addEventListener("pointermove", handlePointerMove);
    window.addEventListener("pointerup", stopResizing);
    window.addEventListener("pointercancel", stopResizing);
    document.body.style.userSelect = "none";
    document.body.style.cursor = "col-resize";

    return () => {
      window.removeEventListener("pointermove", handlePointerMove);
      window.removeEventListener("pointerup", stopResizing);
      window.removeEventListener("pointercancel", stopResizing);
      document.body.style.userSelect = "";
      document.body.style.cursor = "";
    };
  }, [isResizing, side, minWidth, maxWidth, onWidthChange]);

  const handlePointerDown = (event: React.PointerEvent) => {
    event.preventDefault();
    setIsResizing(true);
  };

  return (
    <div className="flex h-full flex-shrink-0" style={{ width: isCollapsed ? 'auto' : width }}>
      {side === "right" && !isCollapsed && (
        <div
          onPointerDown={handlePointerDown}
          className="w-2 flex-shrink-0 cursor-col-resize group flex items-center justify-center -ml-2 z-10 relative"
          title="Resize right panel"
        >
          <div className={`h-[96%] w-[3px] rounded-full transition-colors ${isResizing ? "bg-cyan-400/80" : "bg-indigo-500/25 group-hover:bg-cyan-400/50"}`} />
        </div>
      )}
      
      <div className="h-full w-full flex-1">
        {React.cloneElement(children as React.ReactElement, { width: isCollapsed ? undefined : width } as any)}
      </div>

      {side === "left" && !isCollapsed && (
        <div
          onPointerDown={handlePointerDown}
          className="w-2 flex-shrink-0 cursor-col-resize group flex items-center justify-center -mr-2 z-10 relative"
          title="Resize left panel"
        >
          <div className={`h-[96%] w-[3px] rounded-full transition-colors ${isResizing ? "bg-cyan-400/80" : "bg-indigo-500/25 group-hover:bg-cyan-400/50"}`} />
        </div>
      )}
    </div>
  );
}
