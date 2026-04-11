"use client";
import React, { useEffect } from 'react';
import ReactFlow, { Background, Controls, useNodesState, useEdgesState, Handle, Position } from 'reactflow';
import 'reactflow/dist/style.css';

const CustomNode = ({ data }: any) => {
  const getSeverityStyle = (severity: string) => {
    switch (severity?.toUpperCase()) {
      case "P1":
      case "CRITICAL":
      case "HIGH":
        return "bg-red-500 text-white shadow-[0_0_8px_#ef4444]";
      case "P2":
      case "MEDIUM":
        return "bg-orange-500 text-white shadow-[0_0_8px_#f97316]";
      case "P3":
      case "LOW":
        return "bg-yellow-500 text-black shadow-[0_0_8px_#eab308]";
      case "P4":
      case "INFO":
        return "bg-cyan-500 text-black shadow-[0_0_8px_#06b6d4]";
      default:
        return "bg-slate-500 text-white shadow-[0_0_8px_#64748b]";
    }
  };

  return (
    <>
      <Handle type="target" position={Position.Top} className="!w-1 !h-1 !bg-cyan-400 !border-none" />
      {data.severity && (
        <div 
          className={`absolute -top-2 -right-2 w-5 h-5 rounded-full flex items-center justify-center text-[8px] font-black z-10 ${getSeverityStyle(data.severity)}`}
        >
          {data.severity}
        </div>
      )}
      <div>{data.label}</div>
      <Handle type="source" position={Position.Bottom} className="!w-1 !h-1 !bg-cyan-400 !border-none" />
    </>
  );
};

const nodeTypes = {
  custom: CustomNode,
};

interface GraphProps {
  initialData?: {
    nodes: any[];
    edges: any[];
  } | null;
}

export default function AttackPathGraph({ initialData }: GraphProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  useEffect(() => {
    if (initialData) {
      // Auto-layout simple spacing for now
      const layoutNodes = initialData.nodes.map((node, i) => ({
        ...node,
        position: { x: (i % 3) * 250, y: Math.floor(i / 3) * 150 }
      }));
      setNodes(layoutNodes);
      setEdges(initialData.edges);
    }
  }, [initialData, setNodes, setEdges]);

  return (
    <div className="h-full w-full">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        fitView
      >
        <Background color="#1e293b" gap={20} />
        <Controls className="bg-slate-900 border-white/10 fill-white" />
      </ReactFlow>
    </div>
  );
}