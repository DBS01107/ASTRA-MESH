"use client";
import React, { useCallback, useEffect, useState } from 'react';
import ReactFlow, {
  Background,
  Controls,
  useNodesState,
  useEdgesState,
  NodeMouseHandler,
} from 'reactflow';
import dagre from 'dagre';
import 'reactflow/dist/style.css';
import AssetNode from './AssetNode';
import NodeDetailDrawer from './NodeDetailDrawer';

// Map the possible object types to AssetNode so they inherit our styling & logic
// Defined outside the component to avoid ReactFlow warning about new object on every render
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

interface AttackPathGraphProps {
  initialData: any;
  /** Optional callback so the graph can pre-fill the AI chat */
  onAskAI?: (context: string) => void;
}

export default function AttackPathGraph({ initialData, onAskAI }: AttackPathGraphProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [selectedNode, setSelectedNode] = useState<any | null>(null);

  useEffect(() => {
    if (initialData && initialData.nodes && initialData.edges) {
      const layoutedNodes = getLayoutedElements(
        [...initialData.nodes],
        [...initialData.edges]
      );

      setNodes((currentNodes) => {
        return layoutedNodes.map((node: any) => {
          // If the user has manually dragged a node, preserve their position
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
        minZoom={0.2}
        maxZoom={1.5}
      >
        <Background color="#1e293b" gap={25} size={1} />
        <Controls className="bg-slate-900 border-white/10 fill-cyan-500" />
      </ReactFlow>

      {/* Node detail drawer — scoped inside graph container for absolute positioning */}
      <NodeDetailDrawer
        node={selectedNode}
        onClose={() => setSelectedNode(null)}
        onAskAI={onAskAI}
      />
    </div>
  );
}