import "./globals.css";
import { ToastProvider } from "@/components/ui/Toast";

export const metadata = {
  title: "ASTRA – Vulnerability Orchestrator",
  description: "AI-powered attack path & risk analysis",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-black text-white antialiased">
        <ToastProvider>
          {children}
        </ToastProvider>
        {/* Toast progress animation */}
        <style>{`
          @keyframes toast-progress {
            from { width: 100%; }
            to   { width: 0%; }
          }
        `}</style>
      </body>
    </html>
  );
}
