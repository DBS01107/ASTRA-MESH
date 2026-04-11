"use client";
import React, { useState, useEffect } from "react";
import { Joyride, Step, STATUS } from "react-joyride";

interface TourProps {
  currentUser: any;
}

export default function TourGuide({ currentUser }: TourProps) {
  const [run, setRun] = useState(false);
  const [showPrompt, setShowPrompt] = useState(false);

  useEffect(() => {
    if (typeof window !== "undefined" && currentUser?.username) {
      const tourKey = `astra_tour_completed_${currentUser.username}`;
      const hasSeen = localStorage.getItem(tourKey);

      if (!hasSeen) {
        setTimeout(() => setShowPrompt(true), 1500);
      }
    }
  }, [currentUser]);

  const handleStartTour = () => {
    setShowPrompt(false);
    setRun(true);
  };

  const handleSkipTour = () => {
    setShowPrompt(false);
    localStorage.setItem(`astra_tour_completed_${currentUser.username}`, "true");
  };

  const handleJoyrideCallback = (data: any) => {
    const { status } = data;
    const finishedStatuses: string[] = [STATUS.FINISHED, STATUS.SKIPPED];

    if (finishedStatuses.includes(status)) {
      localStorage.setItem(`astra_tour_completed_${currentUser.username}`, "true");
      setRun(false);
    }
  };

  const steps: any[] = [
    {
      target: "#tour-topbar",
      content: "Welcome to ASTRA OS! This is your SOC Command topbar indicating your secure session identity.",
      disableBeacon: true,
      placement: "bottom",
    },
    {
      target: "#tour-target",
      content: "Enter your target domain or IP here. ASTRA will execute reconnaissance and attack emulation against this vector.",
      placement: "right",
    },
    {
      target: "#tour-modules",
      content: "Select the specific vulnerability modules here. NVD, exploits, or brute-force. Choose exactly what vector to engage.",
      placement: "right",
    },
    {
      target: "#tour-actions",
      content: "Initialize the scan here. You can also interrupt a scan midway, or download an automated PDF compliance report.",
      placement: "right",
    },
    {
      target: "#tour-graph",
      content: "This is the live Attack Path Map! ASTRA charts out discovered assets and maps critical P1-P4 CVEs naturally over time as node relationships.",
      placement: "center",
    },
    {
      target: "#tour-explain",
      content: "Your Gemini AI Co-Pilot analyzes logs and zero-day threat intelligence seamlessly here as the scan runs.",
      placement: "left",
    }
  ];

  const joyrideProps: any = {
    steps,
    run,
    continuous: true,
    onEvent: handleJoyrideCallback,
    styles: {
      options: {
        arrowColor: "#02030a",
        backgroundColor: "#02030a",
        overlayColor: "rgba(0, 0, 0, 0.8)",
        primaryColor: "#22d3ee",
        textColor: "#eaeaf0",
        zIndex: 10000,
      },
      tooltip: {
        border: "1px solid rgba(34, 211, 238, 0.4)",
        borderRadius: "8px",
        fontFamily: "'SairaStencil', monospace",
      },
      tooltipContainer: {
        textAlign: "left",
        fontSize: "13px",
      },
      buttonNext: {
        backgroundColor: "#22d3ee",
        color: "#000",
        fontSize: "11px",
        textTransform: "uppercase",
        letterSpacing: "0.1em",
        padding: "8px 12px",
        borderRadius: "2px",
        fontWeight: "bold",
      },
      buttonBack: {
        color: "#22d3ee",
        fontSize: "10px",
        textTransform: "uppercase",
      },
      buttonSkip: {
        color: "#ef4444",
        fontSize: "10px",
        textTransform: "uppercase",
      }
    }
  };

  return (
    <>
      {showPrompt && (
        <div className="fixed inset-0 z-[10000] flex items-center justify-center bg-black/80 backdrop-blur-sm">
          <div className="glass p-6 rounded-lg border border-cyan-400/50 flex flex-col items-center gap-4 text-center max-w-sm">
            <h2 className="text-2xl font-bold text-cyan-400 font-['SairaStencil'] tracking-widest uppercase">Astra Mesh</h2>
            <p className="text-xs text-slate-300">Would you like a quick walkthrough of the SOC Command capabilities?</p>
            <div className="flex gap-4 mt-2">
              <button 
                onClick={handleStartTour} 
                className="px-6 py-2 bg-cyan-500/20 text-cyan-300 border border-cyan-400/50 rounded hover:bg-cyan-500/40 uppercase text-xs font-bold tracking-widest transition-all"
              >
                Start Tour
              </button>
              <button 
                onClick={handleSkipTour} 
                className="px-6 py-2 bg-transparent text-slate-400 hover:text-rose-400 uppercase text-[10px] font-bold tracking-widest transition-all"
              >
                Skip
              </button>
            </div>
          </div>
        </div>
      )}
      <Joyride {...joyrideProps} />
    </>
  );
}
