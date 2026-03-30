import { create } from 'zustand'; //

interface ScanState {
  selectedNodeId: string | null;
  activeVulnerabilities: any[];
  isMitigating: boolean;
  setSelectedNode: (id: string | null) => void;
  setMitigating: (status: boolean) => void;
  addVulnerability: (vuln: any) => void;
}

export const useScanStore = create<ScanState>((set) => ({
  selectedNodeId: null,
  activeVulnerabilities: [],
  isMitigating: false,
  setSelectedNode: (id) => set({ selectedNodeId: id }),
  setMitigating: (status) => set({ isMitigating: status }),
  addVulnerability: (vuln) => set((state) => ({ 
    activeVulnerabilities: [vuln, ...state.activeVulnerabilities] 
  })),
}));