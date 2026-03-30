"use client";

import ReactFlow, { Background, Controls } from "reactflow";
import "reactflow/dist/style.css";

export default function AttackGraph({ nodes, edges }: any) {
  return (
    <div className="h-[300px] border border-white/10 rounded">
      <ReactFlow nodes={nodes} edges={edges} fitView>
        <Background />
        <Controls />
      </ReactFlow>
    </div>
  );
}
