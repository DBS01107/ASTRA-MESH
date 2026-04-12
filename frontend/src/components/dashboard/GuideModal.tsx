"use client";

import React, { useState } from "react";
import { ChevronRight, ChevronLeft, Target, Shield, Cpu, Share2, FileDown, X } from "lucide-react";

interface GuideModalProps {
  onClose: () => void;
}

export default function GuideModal({ onClose }: GuideModalProps) {
  const [step, setStep] = useState(0);

  const steps = [
    {
      title: "Welcome to ASTRA-MESH",
      icon: <Shield className="w-16 h-16 text-cyan-400 mb-6 drop-shadow-[0_0_15px_#22d3ee]" />,
      content: "ASTRA-MESH is an intelligent Vulnerability Orchestrator designed to map out vulnerabilities like a real attacker. Even if you're not a cybersecurity expert, ASTRA-MESH's built-in AI does the heavy lifting for you.",
      action: "Next: Configuring a Scan"
    },
    {
      title: "Step 1: The Target",
      icon: <Target className="w-16 h-16 text-emerald-400 mb-6 drop-shadow-[0_0_15px_#34d399]" />,
      content: "On the left menu, enter your 'Target' (e.g. scanme.nmap.org). Then select the Modules you want to use. Not sure which to pick? The next page explains what they do.",
      action: "Next: Module Breakdown"
    },
    {
      title: "Scanner Modules",
      icon: null,
      content: "",
      customView: (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-left w-full mt-2 max-h-[300px] overflow-y-auto custom-scrollbar px-2">
          {[{name: "Nmap", desc: "Maps your network. Finds 'open doors' (open ports) and tells you what services are running behind them."},
            {name: "WhatWeb", desc: "Fingerprints websites to figure out exactly what software stack or CMS (like WordPress) is powering them."},
            {name: "Nuclei", desc: "A rapid template-based vulnerability scanner. It tests those 'open doors' against thousands of known flaws."},
            {name: "Nikto", desc: "A classic web server scanner. Looks for dangerous default files, misconfigurations, and outdated server versions."},
            {name: "WPScan & JoomScan", desc: "Highly specialized scanners that only run if WordPress or Joomla is detected, checking for bad plugins or known exploits."},
            {name: "SQLMap", desc: "Tests web forms to see if it can trick the database into handing over data via SQL Injection."}
          ].map(mod => (
            <div key={mod.name} className="bg-slate-900/60 border border-indigo-500/20 p-3 rounded-lg hover:border-cyan-400/40 transition-colors">
              <h3 className="text-cyan-400 font-bold text-sm mb-1 uppercase tracking-wider">{mod.name}</h3>
              <p className="text-slate-400 text-xs leading-relaxed">{mod.desc}</p>
            </div>
          ))}
        </div>
      ),
      action: "Next: Understanding AI Dynamic Mode"
    },
    {
      title: "Step 2: Dynamic Mode",
      icon: <Cpu className="w-16 h-16 text-amber-400 mb-6 drop-shadow-[0_0_15px_#fbbf24]" />,
      content: "Select 'Dynamic' mode. This allows ASTRA-MESH to read results from scanners and automatically launch new ones when it finds something interesting. The right panel shows you exactly what it's thinking in real-time.",
      action: "Next: The Attack Graph"
    },
    {
      title: "Step 3: Attack Paths",
      icon: <Share2 className="w-16 h-16 text-indigo-400 mb-6 drop-shadow-[0_0_15px_#818cf8]" />,
      content: "As the scan runs, the center screen draws a live 'Attack Graph'. Each node represents an open port, service, or vulnerability. Red lines mean the AI found an active threat path you should investigate.",
      action: "Next: Exporting Reports"
    },
    {
      title: "Step 4: Take Action",
      icon: <FileDown className="w-16 h-16 text-rose-400 mb-6 drop-shadow-[0_0_15px_#fb7185]" />,
      content: "When the scan finishes (or you stop it), click 'Download Report' on the bottom left. ASTRA-MESH compiles everything into an Executive Summary PDF that you can hand straight to an IT professional.",
      action: "Start Using ASTRA-MESH"
    }
  ];

  const handleNext = () => {
    if (step < steps.length - 1) setStep(step + 1);
    else onClose();
  };

  const handlePrev = () => {
    if (step > 0) setStep(step - 1);
  };

  const current = steps[step];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Background overlay with heavy blur */}
      <div className="absolute inset-0 bg-[#02030a]/80 backdrop-blur-xl" />
      
      {/* Modal Container */}
      <div className="relative w-full max-w-2xl glass border border-cyan-400/30 rounded-2xl overflow-hidden shadow-[0_0_50px_rgba(34,211,238,0.15)] flex flex-col corner-hud">
        {/* Cyber scanline effect */}
        <div className="scanline" />
        
        {/* Header */}
        <div className="flex justify-between items-center p-4 border-b border-indigo-500/20 bg-indigo-500/10 z-10 relative">
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 bg-cyan-400 rounded-full animate-pulse shadow-[0_0_8px_#22d3ee]" />
            <span className="text-xs font-black tracking-widest text-cyan-400 uppercase">ASTRA-MESH // HANDBOOK</span>
          </div>
          <button 
            onClick={onClose}
            className="text-slate-400 hover:text-cyan-400 transition-colors p-1"
          >
            <X size={18} />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-10 flex flex-col items-center text-center min-h-[350px] justify-center relative z-10">
          {/* Animated step transition wrapper could go here, but using simple state replacement for now */}
          <div className="flex flex-col items-center animate-in fade-in zoom-in duration-500">
            {current.icon}
            <h2 className="text-3xl font-bold uppercase tracking-widest text-white mb-6 font-['SairaStencil']">
              {current.title}
            </h2>
            {current.customView ? current.customView : (
              <p className="text-sm md:text-base text-slate-300 max-w-xl leading-relaxed">
                {current.content}
              </p>
            )}
          </div>
        </div>

        {/* Footer Navigation */}
        <div className="flex items-center justify-between p-6 border-t border-indigo-500/20 bg-black/40 z-10 relative">
          <div className="flex gap-2">
            {steps.map((_, i) => (
              <div 
                key={i} 
                className={`h-1 rounded-full transition-all duration-300 ${
                  i === step ? "w-8 bg-cyan-400 shadow-[0_0_8px_#22d3ee]" : "w-2 bg-slate-700"
                }`}
              />
            ))}
          </div>

          <div className="flex items-center gap-4">
            {step > 0 && (
              <button 
                onClick={handlePrev}
                className="text-xs font-bold tracking-widest uppercase text-slate-400 hover:text-cyan-400 flex items-center gap-1 transition-colors"
              >
                <ChevronLeft size={16} /> Back
              </button>
            )}
            <button 
              onClick={handleNext}
              className="text-xs font-bold tracking-widest uppercase bg-cyan-500/25 border border-cyan-400/50 text-cyan-300 px-6 py-2.5 rounded hover:bg-cyan-400/40 hover:shadow-[0_0_15px_#22d3ee] flex items-center gap-2 transition-all"
            >
              {current.action} 
              {step < steps.length - 1 && <ChevronRight size={16} />}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
