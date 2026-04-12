"use client";

import React from "react";
import { Joyride, Step, STATUS } from "react-joyride";

interface TourGuideProps {
  run: boolean;
  onFinish: () => void;
}

export default function TourGuide({ run, onFinish }: TourGuideProps) {
  const steps: Step[] = [
    {
      target: ".tour-target",
      content: "Enter your target's IP or Domain here. ASTRA-MESH will begin scanning from this entry point.",
      placement: "right"
    },
    {
      target: ".tour-mode",
      content: "Choose 'Dynamic' to let ASTRA-MESH's AI automatically launch new scans based on findings, or 'Static' to run exactly what you select.",
      placement: "right"
    },
    {
      target: ".tour-modules",
      content: "Select the specific security tools you want to run. If unsure, Nmap and Nuclei give a great baseline.",
      placement: "right"
    },
    {
      target: ".tour-graph",
      content: "Watch the scanner build an Attack Graph in real-time. Red lines show active threat paths discovered by the AI.",
      placement: "left"
    },
    {
      target: ".tour-ai",
      content: "The Reasoning Engine analyzes raw logs and explains vulnerabilities in plain English. You can even chat with it! Start the scan to see it in action.",
      placement: "left"
    }
  ];

  const handleJoyrideCallback = (data: any) => {
    const { status } = data;
    const finishedStatuses: string[] = [STATUS.FINISHED, STATUS.SKIPPED];
    if (finishedStatuses.includes(status)) {
      onFinish();
    }
  };

  return (
    <Joyride
      steps={steps}
      run={run}
      continuous
      scrollToFirstStep
      showProgress
      showSkipButton
      callback={handleJoyrideCallback}
      options={{
        arrowColor: "rgba(30, 27, 75, 0.95)",
        backgroundColor: "#02030a",
        overlayColor: "rgba(2, 3, 10, 0.8)",
        primaryColor: "#22d3ee",
        textColor: "#cbd5e1",
        width: 380,
        zIndex: 1000,
      }}
      styles={{
        tooltip: {
          border: "1px solid rgba(34, 211, 238, 0.4)", // cyan border
          borderRadius: "8px",
          fontFamily: "var(--font-mono, monospace)",
          boxShadow: "0 0 20px rgba(34, 211, 238, 0.15)",
        },
        tooltipContainer: {
          textAlign: "left",
          fontSize: "12px",
          lineHeight: "1.6",
          padding: "16px",
        },
        tooltipTitle: {
          color: "#fff",
          fontFamily: "'SairaStencil', sans-serif",
          fontSize: "16px",
          textTransform: "uppercase",
          letterSpacing: "2px",
        },
        buttonNext: {
          backgroundColor: "rgba(34, 211, 238, 0.15)", // cyan-400/15
          border: "1px solid rgba(34, 211, 238, 0.5)",
          color: "#22d3ee",
          fontFamily: "var(--font-mono, monospace)",
          fontSize: "10px",
          textTransform: "uppercase",
          letterSpacing: "0.1em",
          borderRadius: "4px",
          padding: "8px 16px",
          transition: "all 0.3s ease",
        },
        buttonBack: {
          color: "#94a3b8", // slate-400
          fontFamily: "var(--font-mono, monospace)",
          fontSize: "10px",
          textTransform: "uppercase",
          marginRight: "10px",
        },
        buttonSkip: {
          color: "#94a3b8", // slate-400
          fontFamily: "var(--font-mono, monospace)",
          fontSize: "10px",
          textTransform: "uppercase",
        }
      }}
      locale={{
        last: "Start Astra",
        skip: "Skip Tour",
        next: "Next",
        back: "Back",
      }}
    />
  );
}
