"use client";
import React, { useEffect } from 'react';
import ReactFlow, { Background, Controls, useNodesState, useEdgesState } from 'reactflow';
import 'reactflow/dist/style.css';

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
        fitView
      >
        <Background color="#1e293b" gap={20} />
        <Controls className="bg-slate-900 border-white/10 fill-white" />
      </ReactFlow>
    </div>
  );
}