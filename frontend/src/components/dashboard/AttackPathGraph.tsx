"use client";
import React, { useEffect } from 'react';
import ReactFlow, {
  Background,
  Controls,
  useNodesState,
  useEdgesState
} from 'reactflow';
import dagre from 'dagre';
import 'reactflow/dist/style.css';
import AssetNode from './AssetNode';

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

export default function AttackPathGraph({ initialData }: { initialData: any }) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

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

  return (
    <div className="h-full w-full bg-[#020617]">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        fitView
        // Standard interaction settings for the ASTRA dashboard
        minZoom={0.2}
        maxZoom={1.5}
      >
        <Background color="#1e293b" gap={25} size={1} />
        <Controls className="bg-slate-900 border-white/10 fill-cyan-500" />
      </ReactFlow>
    </div>
  );
}