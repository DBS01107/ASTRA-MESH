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
      // Use functional state update to access the true most recent nodes, avoiding stale closure states!
      setNodes((currentNodes) => {
        return initialData.nodes.map((node: any, i: number) => {
          // Avoid resetting user-dragged manual coordinates if the node already exists in state
          const existingNode = currentNodes.find((n: any) => n.id === node.id);
          const targetPosition = existingNode ? existingNode.position : {
            x: (i % 3) * 250,
            y: Math.floor(i / 3) * 150
          };

          return {
            ...node,
            // Explicitly set the type so React Flow cleanly maps to the proper AssetNode
            type: node.type || node.data?.type || 'asset',
            // Forcibly clear out any backend-injected CSS styling classes that create extra boxes!
            className: "",
            position: targetPosition,
            data: {
              ...node.data,
              id: node.id
            }
          };
        });
      });

      // Ensure edges map appropriately too and don't get completely overridden without cause
      setEdges(initialData.edges || []);
    }
    // Remove nodes from dependencies to avoid infinite loops when preserving existing positions
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