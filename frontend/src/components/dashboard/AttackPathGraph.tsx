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

const dagreGraph = new dagre.graphlib.Graph();
dagreGraph.setDefaultEdgeLabel(() => ({}));

const nodeWidth = 250;
const nodeHeight = 80;

const getLayoutedElements = (nodes: any[], edges: any[], direction = 'LR') => {
  dagreGraph.setGraph({ rankdir: direction });

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: nodeWidth, height: nodeHeight });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  return nodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    return {
      ...node,
      targetPosition: 'left',
      sourcePosition: 'right',
      position: {
        x: nodeWithPosition.x - nodeWidth / 2,
        y: nodeWithPosition.y - nodeHeight / 2,
      },
    };
  });
};

export default function AttackPathGraph({ initialData }: { initialData: any }) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  useEffect(() => {
    if (initialData && initialData.nodes && initialData.edges) {
      // First calculate the ideal layout using dagre
      const layoutedNodes = getLayoutedElements(
        [...initialData.nodes],
        [...initialData.edges]
      );

      setNodes((currentNodes) => {
        return layoutedNodes.map((node: any) => {
          // If the user has manually forcibly dragged a node, we preserve their coordinate overrides!
          const existingNode = currentNodes.find((n: any) => n.id === node.id);

          return {
            ...node,
            type: node.type || node.data?.type || 'asset',
            className: "",
            position: existingNode ? existingNode.position : node.position,
            data: {
              ...node.data,
              id: node.id
            }
          };
        });
      });

      setEdges(initialData.edges);
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