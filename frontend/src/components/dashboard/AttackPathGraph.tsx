"use client";
import React, { useCallback, useEffect, useState } from 'react';
import ReactFlow, {
  Background,
  Controls,
  useNodesState,
  useEdgesState,
  NodeMouseHandler,
} from 'reactflow';
import 'reactflow/dist/style.css';
import AssetNode from './AssetNode';
import NodeDetailDrawer from './NodeDetailDrawer';

// Map the possible object types to AssetNode so they inherit our styling & logic
const nodeTypes = {
  asset: AssetNode,
  finding: AssetNode,
  impact: AssetNode,
  unknown: AssetNode,
  host: AssetNode,
  port: AssetNode,
  open_port: AssetNode,
  service: AssetNode,
  web_service: AssetNode,
  vulnerability: AssetNode,
  custom: AssetNode
};

interface AttackPathGraphProps {
  initialData: any;
  /** Optional callback so the graph can pre-fill the AI chat */
  onAskAI?: (context: string) => void;
  isScanning?: boolean;
  scanElapsed?: number;
}

const formatTime = (seconds: number) => {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
};

export default function AttackPathGraph({ initialData, onAskAI, isScanning, scanElapsed = 0 }: AttackPathGraphProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [selectedNode, setSelectedNode] = useState<any | null>(null);

  useEffect(() => {
    if (initialData && initialData.nodes) {
      setNodes((currentNodes) => {
        return initialData.nodes.map((node: any, i: number) => {
          // If the user has manually forcibly dragged a node, we preserve their coordinate overrides!
          const existingNode = currentNodes.find((n: any) => n.id === node.id);

          return {
            ...node,
            type: node.type || node.data?.type || 'asset',
            className: "",
            position: existingNode ? existingNode.position : { x: (i % 3) * 250, y: Math.floor(i / 3) * 150 },
            data: {
              ...node.data,
              id: node.id
            }
          };
        });
      });

      setEdges(initialData.edges || []);
    }
  }, [initialData, setNodes, setEdges]);

  const handleNodeClick: NodeMouseHandler = useCallback((_event, node) => {
    setSelectedNode(node);
  }, []);

  const handlePaneClick = useCallback(() => {
    setSelectedNode(null);
  }, []);

  return (
    <div className="h-full w-full bg-[#020617] relative">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={handleNodeClick}
        onPaneClick={handlePaneClick}
        fitView
        // Standard interaction settings for the ASTRA dashboard
        minZoom={0.2}
        maxZoom={1.5}
      >
        <Background color="#1e293b" gap={25} size={1} />
        <Controls className="bg-slate-900 border-white/10 fill-cyan-500" />
      </ReactFlow>

      {/* Stopwatch Overlay — Top Right */}
      <div className="absolute top-5 right-5 z-[50] pointer-events-none select-none">
        <div className="flex flex-col items-end">
          <div className="flex items-center gap-2 px-4 py-2 bg-black/40 backdrop-blur-md border border-white/10 rounded-lg shadow-[0_0_20px_rgba(255,255,255,0.05)] transition-all duration-300">
            {isScanning && (
              <div className="flex items-center gap-2 mr-2 border-r border-white/10 pr-3">
                <div className="w-1.5 h-1.5 bg-white rounded-full animate-pulse shadow-[0_0_8px_#fff]" />
                <span className="text-[9px] font-black tracking-[0.2em] text-white/60 uppercase">Live</span>
              </div>
            )}
            <div 
              style={{
                fontFamily: "'Courier New', Courier, monospace", // Fallback to digital-looking mono
                letterSpacing: '0.1em',
                textShadow: '0 0 10px rgba(255,255,255,0.3)'
              }}
              className="text-2xl font-bold text-white tabular-nums"
            >
              {formatTime(scanElapsed)}
            </div>
          </div>
          <div className="mt-1 mr-1 text-[8px] font-bold tracking-[0.3em] text-white/30 uppercase">
            Mission_Duration
          </div>
        </div>
      </div>

      {/* Node detail drawer — scoped inside graph container for absolute positioning */}
      <NodeDetailDrawer
        node={selectedNode}
        onClose={() => setSelectedNode(null)}
        onAskAI={onAskAI}
      />
    </div>
  );
}