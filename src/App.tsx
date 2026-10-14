import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";
import "./App.css";

function App() {
  const [tab, setTab] = useState<"split" | "restore">("split");

  // Shared Progress State
  const [progress, setProgress] = useState(0);
  const [eta, setEta] = useState(0);
  const [processMsg, setProcessMsg] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);

  // Split State
  const [inputDir, setInputDir] = useState("");
  const [vaultName, setVaultName] = useState("my_secure_vault");
  const [outputDir, setOutputDir] = useState("");
  const [threshold, setThreshold] = useState(3);
  const [totalShares, setTotalShares] = useState(5);
  const [splitStatus, setSplitStatus] = useState("");

  // Restore State
  const [sharePaths, setSharePaths] = useState<string[]>([]);
  const [restoreOutputDir, setRestoreOutputDir] = useState("");
  const [restoreStatus, setRestoreStatus] = useState("");

  useEffect(() => {
    const unlistenSplit = listen<{ percent: number; eta_seconds: number }>("split-progress", (e) => {
      setProgress(e.payload.percent);
      setEta(e.payload.eta_seconds);
    });
    const unlistenRestore = listen<{ percent: number; eta_seconds: number }>("restore-progress", (e) => {
      setProgress(e.payload.percent);
      setEta(e.payload.eta_seconds);
    });
    const unlistenStatus = listen<string>("status-msg", (e) => {
      setProcessMsg(e.payload);
    });

    return () => {
      unlistenSplit.then((f) => f());
      unlistenRestore.then((f) => f());
      unlistenStatus.then((f) => f());
    };
  }, []);

  const handleSelectDir = async (setter: React.Dispatch<React.SetStateAction<string>>) => {
    const selected = await open({ directory: true });
    if (selected && typeof selected === "string") setter(selected);
  };

  const handleSelectShares = async () => {
    const selected = await open({ multiple: true, filters: [{ name: "Ombracrux Shares", extensions: ["ombracrx"] }] });
    if (selected && Array.isArray(selected)) setSharePaths(selected);
  };

  const resetProgress = () => {
    setProgress(0);
    setEta(0);
    setProcessMsg("");
    setIsProcessing(true);
  };

  const formatEta = (secs: number) => {
    if (secs === 0) return "Calculating...";
    return secs > 60 ? `${Math.floor(secs / 60)}m ${Math.floor(secs % 60)}s remaining` : `${Math.floor(secs)}s remaining`;
  };

  const handleSplit = async () => {
    if (!inputDir || !outputDir || !vaultName) {
      setSplitStatus("Please select an input directory, a vault name, and an output directory.");
      return;
    }
    resetProgress();
    setSplitStatus("");
    try {
      await invoke("split_action", { inputDir, vaultName, outputDir, threshold, totalShares });
      setSplitStatus("Success: Shares created safely.");
    } catch (err) {
      setSplitStatus(`Error: ${err}`);
      setProcessMsg("Operation failed.");
    }
    setIsProcessing(false);
  };

  const handleRestore = async () => {
    if (sharePaths.length === 0 || !restoreOutputDir) {
      setRestoreStatus("Please select share files and an extraction folder.");
      return;
    }
    resetProgress();
    setRestoreStatus("");
    try {
      const result = await invoke<string>("restore_action", {
      sharePaths,
      outputDir: restoreOutputDir,
    });
    setRestoreStatus(result);
    } catch (err) {
      setRestoreStatus(`Error: ${err}`);
      setProcessMsg("Operation failed.");
    }
    setIsProcessing(false);
  };

  return (
    <div className="container">
      <h1>Ombracrux</h1>
      <p className="subtitle">Post-Quantum Resilient Threshold Storage</p>

      <div className="tabs">
        <button className={tab === "split" ? "active" : ""} onClick={() => setTab("split")} disabled={isProcessing}>Split</button>
        <button className={tab === "restore" ? "active" : ""} onClick={() => setTab("restore")} disabled={isProcessing}>Restore</button>
      </div>

      {tab === "split" && (
        <div className="panel">
          <div className="input-group">
            <label>Folder to Protect</label>
            <div className="file-picker">
              <input type="text" readOnly value={inputDir} placeholder="Select a directory to encrypt..." />
              <button onClick={() => handleSelectDir(setInputDir)} disabled={isProcessing}>Browse</button>
            </div>
          </div>

          <div className="input-group">
            <label>Vault Name</label>
            <input type="text" value={vaultName} onChange={(e) => setVaultName(e.target.value.replace(/[^a-zA-Z0-9_-]/g, ""))} disabled={isProcessing} placeholder="No spaces, e.g., secret_backup" />
          </div>

          <div className="row">
            <div className="input-group">
              <label>Total Shares (N)</label>
              <input type="number" min="2" max="255" value={totalShares} onChange={(e) => setTotalShares(Number(e.target.value))} disabled={isProcessing} />
            </div>
            <div className="input-group">
              <label>Threshold (T)</label>
              <input type="number" min="1" max={totalShares} value={threshold} onChange={(e) => setThreshold(Number(e.target.value))} disabled={isProcessing} />
            </div>
          </div>

          <div className="input-group">
            <label>Output Directory</label>
            <div className="file-picker">
              <input type="text" readOnly value={outputDir} placeholder="Where to save shares..." />
              <button onClick={() => handleSelectDir(setOutputDir)} disabled={isProcessing}>Browse</button>
            </div>
          </div>

          <button className="primary-btn" onClick={handleSplit} disabled={isProcessing}>
            {isProcessing ? "Processing..." : "Create Secure Shares"}
          </button>
          
          {processMsg && <div className="process-msg">{processMsg}</div>}
          {isProcessing && (
            <div className="progress-area">
              <div className="progress-bar-container">
                <div className="progress-bar" style={{ width: `${progress}%` }}></div>
              </div>
              <div className="progress-stats">
                <span>{progress.toFixed(1)}%</span>
                <span>{formatEta(eta)}</span>
              </div>
            </div>
          )}

          {splitStatus && <div className="status-box">{splitStatus}</div>}
        </div>
      )}

      {tab === "restore" && (
        <div className="panel">
          <div className="input-group">
            <label>Select Shares (.ombracrx)</label>
            <div className="file-picker">
              <input type="text" readOnly value={sharePaths.length > 0 ? `${sharePaths.length} shares selected` : ""} placeholder="Select parts..." />
              <button onClick={handleSelectShares} disabled={isProcessing}>Browse</button>
            </div>
          </div>

          <div className="input-group">
            <label>Extraction Folder</label>
            <div className="file-picker">
              <input type="text" readOnly value={restoreOutputDir} placeholder="Where to unpack the recovered folder..." />
              <button onClick={() => handleSelectDir(setRestoreOutputDir)} disabled={isProcessing}>Browse</button>
            </div>
          </div>

          <button className="primary-btn" onClick={handleRestore} disabled={isProcessing}>
             {isProcessing ? "Processing..." : "Recover & Unpack"}
          </button>

          {processMsg && <div className="process-msg">{processMsg}</div>}
          {isProcessing && (
            <div className="progress-area">
              <div className="progress-bar-container">
                <div className="progress-bar" style={{ width: `${progress}%` }}></div>
              </div>
              <div className="progress-stats">
                <span>{progress.toFixed(1)}%</span>
                <span>{formatEta(eta)}</span>
              </div>
            </div>
          )}

          {restoreStatus && <div className="status-box">{restoreStatus}</div>}
        </div>
      )}
    </div>
  );
}

export default App;