import { useState } from "react";
import axios from "axios";

function App() {
  const [target, setTarget] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleScan = async () => {
    setLoading(true);
    try {
      const res = await axios.post("http://localhost:4000/api/scan", { target });
      setResult(res.data);
    } catch (err) {
      console.error("Scan error:", err);
      setResult({ error: "Failed to scan target." });
    }
    setLoading(false);
  };

  return (
    <div style={{ padding: 20, fontFamily: "Arial" }}>
      <h1>VAPT Dashboard</h1>
      <input
        value={target}
        onChange={(e) => setTarget(e.target.value)}
        placeholder="Enter IP"
        style={{ padding: 5, marginRight: 10 }}
      />
      <button onClick={handleScan} disabled={loading}>
        {loading ? "Scanning..." : "Scan"}
      </button>

      {result && (
        <div style={{ marginTop: 20 }}>
          {result.error ? (
            <p style={{ color: "red" }}>{result.error}</p>
          ) : (
            <>
              <h2>Target: {result.target}</h2>
              <h3>
                Risk:{" "}
                <span
                  style={{
                    color:
                      result.risk_level === "Critical"
                        ? "red"
                        : result.risk_level === "Warning"
                        ? "orange"
                        : "green",
                  }}
                >
                  {result.risk_level}
                </span>
              </h3>

              <h4>RustScan Output:</h4>
              <ul>
                {result.rustscan.map((item, idx) => (
                  <li key={idx}>
                    <strong>{item.port}</strong> - {item.state} - {item.service}
                  </li>
                ))}
              </ul>

              <h4>OWASP ZAP Findings:</h4>
              <ul>
                {result.zap.map((line, idx) => (
                  <li key={idx}>{line}</li>
                ))}
              </ul>

              <h4>Nuclei Findings:</h4>
              <ul>
                {result.nuclei.map((line, idx) => (
                  <li key={idx}>{line}</li>
                ))}
              </ul>

              <h4>TestSSL Summary:</h4>
              <ul>
                {result.testssl.map((line, idx) => (
                  <li key={idx}>{line}</li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default App;
