/**
 * WebSentry — Pure CLI Tool Documentation & Terminal Console View
 * Developer: Isha Sonaria
 * GitHub: https://github.com/ishasonaria568-prog
 */

export default function App() {
  return (
    <div className="min-h-screen bg-[#07080a] text-[#f1f5f9] font-mono p-4 sm:p-8 selection:bg-red-900 selection:text-white">
      <div className="max-w-4xl mx-auto border border-[#261214] bg-[#0c0d12] rounded-lg shadow-2xl overflow-hidden">
        {/* Terminal Titlebar */}
        <div className="bg-[#140b0d] border-b border-[#261214] px-4 py-3 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 rounded-full bg-[#ef4444]" />
            <div className="w-3 h-3 rounded-full bg-[#eab308]" />
            <div className="w-3 h-3 rounded-full bg-[#22c55e]" />
            <span className="ml-2 text-xs text-neutral-400 font-bold tracking-wider">
              bash — websentry@kali: ~/websentry
            </span>
          </div>
          <span className="text-[11px] bg-red-600 text-white font-extrabold px-2 py-0.5 rounded tracking-widest uppercase">
            CLI-ONLY TOOL
          </span>
        </div>

        {/* Terminal Screen Body */}
        <div className="p-6 text-sm space-y-6 leading-relaxed">
          {/* ASCII Banner */}
          <pre className="text-red-500 font-bold text-xs sm:text-sm overflow-x-auto select-none">
{` __      __      ___.    _________               __                       
/  \\    /  \\ ____\\_ |__ /   _____/____   _______/  |________ ___.__.      
\\   \\/\\/   // __ \\| __ \\\\_____  \\/ __ \\ /    /\\   __\\_  __ <   |  |      
 \\        /\\  ___/| \\_\\ \\        \\  ___/|   |  \\|  |  |  | \\/\\___  |      
  \\__/\\  /  \\___  >___  /_______  /\\___  >___|  /|__|  |__|   / ____|      
       \\/       \\/    \\/        \\/     \\/     \\/             \\/           `}
          </pre>

          {/* Branding Badges */}
          <div className="border-t border-b border-[#261214] py-3 flex flex-wrap items-center justify-between gap-2 text-xs">
            <div className="flex items-center gap-2">
              <span className="bg-red-700 text-white font-black px-2 py-0.5 rounded text-[11px]">
                BUILT BY ISHA SONARIA
              </span>
              <span className="text-neutral-300 font-semibold">Web Server Security Assessment Tool</span>
            </div>
            <div className="text-neutral-400 flex items-center gap-3">
              <span>Version: <strong className="text-red-400">v1.2.0</strong></span>
              <span>&bull;</span>
              <a
                href="https://github.com/ishasonaria568-prog"
                target="_blank"
                rel="noreferrer"
                className="text-cyan-400 hover:underline"
              >
                github.com/ishasonaria568-prog
              </a>
            </div>
          </div>

          {/* CLI Notice */}
          <div className="bg-[#170a0c] border border-red-950 p-4 rounded text-xs text-neutral-300 space-y-2">
            <p className="font-bold text-red-400 flex items-center gap-2">
              <span>[!]</span> WebSentry is a 100% Terminal CLI Application
            </p>
            <p className="text-neutral-400">
              In accordance with design constraints, WebSentry contains no GUI, web forms, or browser scanner dashboard.
              Execute all scans directly from your terminal or Kali Linux command prompt.
            </p>
          </div>

          {/* Quick CLI Execution Commands */}
          <div className="space-y-3">
            <div className="text-xs text-neutral-400 uppercase font-bold tracking-wider">
              Terminal Quick Reference
            </div>

            <div className="space-y-2 font-mono text-xs">
              <div className="bg-[#050608] p-3 rounded border border-neutral-800">
                <span className="text-neutral-500"># 1. Display Version & Author Info</span>
                <p className="text-neutral-200 mt-1">$ websentry version</p>
              </div>

              <div className="bg-[#050608] p-3 rounded border border-neutral-800">
                <span className="text-neutral-500"># 2. Audit Local / Private Web Server</span>
                <p className="text-neutral-200 mt-1">$ websentry scan -u http://127.0.0.1:8080</p>
              </div>

              <div className="bg-[#050608] p-3 rounded border border-neutral-800">
                <span className="text-neutral-500"># 3. Quick Assessment (Critical paths & headers)</span>
                <p className="text-neutral-200 mt-1">$ websentry scan -u http://127.0.0.1:8080 --quick</p>
              </div>

              <div className="bg-[#050608] p-3 rounded border border-neutral-800">
                <span className="text-neutral-500"># 4. Authorized Public Target (Requires --allow-public)</span>
                <p className="text-neutral-200 mt-1">
                  $ websentry scan -u https://authorized-target.com <span className="text-red-400 font-bold">--allow-public</span>
                </p>
              </div>

              <div className="bg-[#050608] p-3 rounded border border-neutral-800">
                <span className="text-neutral-500"># 5. Generate Standalone Interactive HTML Report</span>
                <p className="text-neutral-200 mt-1">
                  $ websentry scan -u http://127.0.0.1:8080 <span className="text-yellow-400">--format html</span>
                </p>
              </div>

              <div className="bg-[#050608] p-3 rounded border border-neutral-800">
                <span className="text-neutral-500"># 6. Global Installation on Kali Linux via pipx</span>
                <p className="text-neutral-200 mt-1">
                  $ git clone https://github.com/ishasonaria568-prog/websentry.git<br />
                  $ cd websentry && pipx install .
                </p>
              </div>
            </div>
          </div>

          {/* Engine Capabilities Summary */}
          <div className="border-t border-[#261214] pt-4 text-xs text-neutral-400 grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <strong className="text-neutral-200 block mb-1">Core Modules:</strong>
              <ul className="list-disc list-inside space-y-1 text-neutral-400">
                <li>HTTP Security Header Audit</li>
                <li>HTTP Methods & Verb Probing (TRACE/PUT/DELETE)</li>
                <li>Server Fingerprinting & Version Disclosure</li>
                <li>Sensitive File Detection (.git, .env, backups)</li>
              </ul>
            </div>
            <div>
              <strong className="text-neutral-200 block mb-1">Security Standards:</strong>
              <ul className="list-disc list-inside space-y-1 text-neutral-400">
                <li>SSL/TLS Certificate Validity & Legacy TLS Checks</li>
                <li>Nikto-Inspired Signature Engine (30+ rules)</li>
                <li>Safety Gatekeeper & Authorization Safeguards</li>
                <li>Zero External Dependencies (Standard Library Ready)</li>
              </ul>
            </div>
          </div>

          {/* Footer Developer Credit */}
          <div className="border-t border-[#261214] pt-4 text-center text-xs text-neutral-500">
            WebSentry v1.2.0 &bull; Developer Credit: <strong className="text-neutral-300">Built by ISHA SONARIA</strong> &bull;{" "}
            <a
              href="https://github.com/ishasonaria568-prog"
              target="_blank"
              rel="noreferrer"
              className="text-cyan-400 hover:underline"
            >
              GitHub Profile
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
