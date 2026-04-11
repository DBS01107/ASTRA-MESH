"use client";
import React, { useEffect, useRef, ReactNode } from 'react';
import PerfectScrollbar from 'perfect-scrollbar';

interface ScrollableProps {
  children: ReactNode;
  className?: string;
  options?: PerfectScrollbar.Options;
  style?: React.CSSProperties;
  onScroll?: (event: Event) => void;
  // Allows parent to access the scrollbar instance or container
  containerRef?: React.RefObject<HTMLDivElement | null>;
}

export default function Scrollable({
  children,
  className = "",
  options = {
    wheelSpeed: 1,
    wheelPropagation: true,
    minScrollbarLength: 20
  },
  style,
  onScroll,
  containerRef: externalRef
}: ScrollableProps) {
  const internalRef = useRef<HTMLDivElement>(null);
  const psRef = useRef<PerfectScrollbar | null>(null);
  
  // Use either external or internal ref
  const activeRef = externalRef || internalRef;

  useEffect(() => {
    if (activeRef.current) {
      // Initialize PerfectScrollbar
      psRef.current = new PerfectScrollbar(activeRef.current, options);
      
      const container = activeRef.current;
      if (onScroll) {
        container.addEventListener('ps-scroll-y', onScroll);
        container.addEventListener('ps-scroll-x', onScroll);
      }

      return () => {
        if (psRef.current) {
          psRef.current.destroy();
          psRef.current = null;
        }
        if (onScroll) {
          container.removeEventListener('ps-scroll-y', onScroll);
          container.removeEventListener('ps-scroll-x', onScroll);
        }
      };
    }
  }, []);

  // Update scrollbar when children change
  useEffect(() => {
    if (psRef.current) {
      psRef.current.update();
    }
  }, [children]);

  return (
    <div 
      ref={activeRef} 
      className={`relative overflow-hidden ${className}`} 
      style={style}
    >
      {children}
    </div>
  );
}
