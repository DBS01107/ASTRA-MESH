import "./globals.css";


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
        {children}
      </body>
    </html>
  );
}
