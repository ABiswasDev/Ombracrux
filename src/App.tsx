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
  const [vaultName, setVaultName] = useState("Ombracrux_Vault");
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

  const handleTabChange = (nextTab: "split" | "restore") => {
    if (isProcessing) return;
    setTab(nextTab);
    setProcessMsg("");
    setSplitStatus("");
    setRestoreStatus("");
    setProgress(0);
    setEta(0);
  };

  const handleSelectDir = async (setter: React.Dispatch<React.SetStateAction<string>>) => {
    const selected = await open({ directory: true });
    if (selected && typeof selected === "string") setter(selected);
  };

  const handleSelectShares = async () => {
    const selected = await open({
      multiple: true,
      filters: [{ name: "Ombracrux Shares", extensions: ["ombracrx"] }],
    });
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
    return secs > 60
      ? `${Math.floor(secs / 60)}m ${Math.floor(secs % 60)}s remaining`
      : `${Math.floor(secs)}s remaining`;
  };

  const handleSplit = async () => {
    if (!inputDir || !outputDir || !vaultName) {
      setProcessMsg("");
      setSplitStatus("Error: Please select an input folder, a vault name, and an output folder.");
      return;
    }
    resetProgress();
    setSplitStatus("");
    try {
      await invoke("split_action", { inputDir, vaultName, outputDir, threshold, totalShares });
    } catch (err) {
      setProcessMsg("");
      setSplitStatus(`Error: ${err}`);
    }
    setIsProcessing(false);
  };

  const handleRestore = async () => {
    if (sharePaths.length === 0 || !restoreOutputDir) {
      setProcessMsg("");
      setRestoreStatus("Error: Please select share files and an output folder.");
      return;
    }
    resetProgress();
    setRestoreStatus("");
    try {
      const result = await invoke<string>("restore_action", {
        sharePaths,
        outputDir: restoreOutputDir,
      });
      setProcessMsg("");
      setRestoreStatus(result);
    } catch (err) {
      setProcessMsg("");
      setRestoreStatus(`Error: ${err}`);
    }
    setIsProcessing(false);
  };

  return (
    <div className="container">
      <div className="header">
        <h1>Ombracrux</h1>
        <p className="subtitle">Shamir Threshold Archive Engine</p>
        <div className="emblem-divider" aria-hidden="true">
          <span className="emblem-line"></span>
          <span className="emblem-diamond">◇</span>
          <span className="emblem-line"></span>
        </div>
      </div>

      <div className="tabs-wrapper">
        <div className="tabs">
          <button
            className={tab === "split" ? "active" : ""}
            onClick={() => handleTabChange("split")}
            disabled={isProcessing}
          >
            Split
          </button>
          <button
            className={tab === "restore" ? "active" : ""}
            onClick={() => handleTabChange("restore")}
            disabled={isProcessing}
          >
            Restore
          </button>
        </div>
      </div>

      {tab === "split" && (
        <div className="panel">
          <div className="input-group">
            <label>Input Folder</label>
            <div className="file-picker">
              <input type="text" readOnly value={inputDir} placeholder="Select a folder to encrypt..." />
              <button onClick={() => handleSelectDir(setInputDir)} disabled={isProcessing}>
                Browse
              </button>
            </div>
          </div>

          <div className="input-group">
            <label>Vault Name</label>
            <input
              type="text"
              value={vaultName}
              onChange={(e) => setVaultName(e.target.value.replace(/[^a-zA-Z0-9_-]/g, ""))}
              disabled={isProcessing}
              placeholder="Ombracrux_Vault"
            />
          </div>

          <div className="row">
            <div className="input-group">
              <label>Total Shares (N)</label>
              <input
                type="number"
                min="2"
                max="255"
                value={totalShares}
                onChange={(e) => setTotalShares(Number(e.target.value))}
                disabled={isProcessing}
              />
            </div>
            <div className="input-group">
              <label>Threshold (T)</label>
              <input
                type="number"
                min="1"
                max={totalShares}
                value={threshold}
                onChange={(e) => setThreshold(Number(e.target.value))}
                disabled={isProcessing}
              />
            </div>
          </div>

          <div className="input-group">
            <label>Output Folder</label>
            <div className="file-picker">
              <input type="text" readOnly value={outputDir} placeholder="Where to save shares..." />
              <button onClick={() => handleSelectDir(setOutputDir)} disabled={isProcessing}>
                Browse
              </button>
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

          {splitStatus && (
            <div className={`status-box ${splitStatus.startsWith("Error:") ? "error" : ""}`}>
              {splitStatus}
            </div>
          )}
        </div>
      )}

      {tab === "restore" && (
        <div className="panel">
          <div className="input-group">
            <label>Input Folder</label>
            <div className="file-picker">
              <input
                type="text"
                readOnly
                value={sharePaths.length > 0 ? `${sharePaths.length} shares selected` : ""}
                placeholder="Select .ombracrx share files..."
              />
              <button onClick={handleSelectShares} disabled={isProcessing}>
                Browse
              </button>
            </div>
          </div>

          <div className="input-group">
            <label>Output Folder</label>
            <div className="file-picker">
              <input
                type="text"
                readOnly
                value={restoreOutputDir}
                placeholder="Where to unpack the recovered folder..."
              />
              <button onClick={() => handleSelectDir(setRestoreOutputDir)} disabled={isProcessing}>
                Browse
              </button>
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

          {restoreStatus && (
            <div className={`status-box ${restoreStatus.startsWith("Error:") ? "error" : ""}`}>
              {restoreStatus}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default App;