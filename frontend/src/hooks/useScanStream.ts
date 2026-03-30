import { apiUrl } from "@/lib/api";
import { withSession } from "@/lib/session";

export function useScanStream(
  _target: string,
  onLog: (l: string) => void,
  sessionId: string = "default"
) {
  const es = new EventSource(apiUrl(withSession("/api/scan/stream", sessionId)));

  es.onmessage = (e) => onLog(e.data);
  es.onerror = () => es.close();

  return () => es.close();
}
