import React, { useState, useEffect } from "react";
import "./App.css";
import axios from "axios";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

function App() {
  const [hashes, setHashes] = useState("");
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState(null);
  const [activeTab, setActiveTab] = useState("analyzer");
  const [customWordlist, setCustomWordlist] = useState("");

  useEffect(() => {
    fetchStats();
    fetchHistory();
  }, []);

  const fetchStats = async () => {
    try {
      const response = await axios.get(`${API}/hash-stats`);
      setStats(response.data);
    } catch (error) {
      console.error("Error fetching stats:", error);
    }
  };

  const fetchHistory = async () => {
    try {
      const response = await axios.get(`${API}/analysis-history`);
      setHistory(response.data);
    } catch (error) {
      console.error("Error fetching history:", error);
    }
  };

  const analyzeHashes = async () => {
    if (!hashes.trim()) {
      alert("Please enter at least one hash to analyze");
      return;
    }

    setLoading(true);
    try {
      const hashList = hashes.split('\n').filter(h => h.trim()).map(h => h.trim());
      const wordlist = customWordlist.trim() ? customWordlist.split('\n').filter(w => w.trim()).map(w => w.trim()) : null;
      
      const response = await axios.post(`${API}/analyze-hashes`, {
        hashes: hashList,
        attack_type: "dictionary",
        custom_wordlist: wordlist
      });
      
      setResults(response.data);
      await fetchStats();
      await fetchHistory();
    } catch (error) {
      console.error("Error analyzing hashes:", error);
      alert("Error analyzing hashes. Please try again.");
    }
    setLoading(false);
  };

  const clearResults = () => {
    setResults(null);
    setHashes("");
    setCustomWordlist("");
  };

  const getStrengthColor = (score) => {
    if (score <= 3) return "text-red-500";
    if (score <= 6) return "text-yellow-500";
    return "text-green-500";
  };

  const getStrengthLabel = (score) => {
    if (score <= 3) return "Weak";
    if (score <= 6) return "Medium";
    return "Strong";
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className="w-10 h-10 bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg flex items-center justify-center">
              <span className="text-white font-bold text-xl">🔐</span>
            </div>
            <div>
              <h1 className="text-2xl font-bold">CyberSec Pro</h1>
              <p className="text-gray-400 text-sm">Password Hash Analysis Engine</p>
            </div>
          </div>
          <div className="text-right text-sm text-gray-400">
            <p>CompTIA Security+ Professional Toolkit</p>
            <p>v1.0.0</p>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav className="bg-gray-800 border-b border-gray-700 px-6 py-3">
        <div className="max-w-7xl mx-auto">
          <div className="flex space-x-8">
            <button
              onClick={() => setActiveTab("analyzer")}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                activeTab === "analyzer"
                  ? "bg-blue-600 text-white"
                  : "text-gray-400 hover:text-white hover:bg-gray-700"
              }`}
            >
              Hash Analyzer
            </button>
            <button
              onClick={() => setActiveTab("history")}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                activeTab === "history"
                  ? "bg-blue-600 text-white"
                  : "text-gray-400 hover:text-white hover:bg-gray-700"
              }`}
            >
              Analysis History
            </button>
            <button
              onClick={() => setActiveTab("stats")}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                activeTab === "stats"
                  ? "bg-blue-600 text-white"
                  : "text-gray-400 hover:text-white hover:bg-gray-700"
              }`}
            >
              Statistics
            </button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* Hash Analyzer Tab */}
        {activeTab === "analyzer" && (
          <div className="space-y-6">
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-xl font-bold mb-4">Hash Analysis</h2>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium mb-2">
                    Password Hashes (one per line)
                  </label>
                  <textarea
                    value={hashes}
                    onChange={(e) => setHashes(e.target.value)}
                    placeholder="Enter hashes here, one per line:
5d41402abc4b2a76b9719d911017c592
098f6bcd4621d373cade4e832627b4f6
e3b0c44298fc1c149afbf4c8996fb924"
                    className="w-full h-32 bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-2">
                    Custom Wordlist (optional)
                  </label>
                  <textarea
                    value={customWordlist}
                    onChange={(e) => setCustomWordlist(e.target.value)}
                    placeholder="Enter custom passwords for dictionary attack:
password123
admin
letmein"
                    className="w-full h-32 bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              </div>
              <div className="mt-6 flex space-x-4">
                <button
                  onClick={analyzeHashes}
                  disabled={loading}
                  className="px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 rounded-lg font-medium transition-colors"
                >
                  {loading ? "Analyzing..." : "Analyze Hashes"}
                </button>
                <button
                  onClick={clearResults}
                  className="px-6 py-3 bg-gray-600 hover:bg-gray-700 rounded-lg font-medium transition-colors"
                >
                  Clear
                </button>
              </div>
            </div>

            {/* Results */}
            {results && (
              <div className="bg-gray-800 rounded-lg p-6">
                <h3 className="text-xl font-bold mb-4">Analysis Results</h3>
                
                {/* Summary */}
                <div className="bg-gray-700 rounded-lg p-4 mb-6">
                  <h4 className="font-semibold mb-2">Summary</h4>
                  <p className="text-gray-300">{results.summary}</p>
                  <div className="mt-2 flex space-x-6 text-sm">
                    <span>Total Time: {results.total_time.toFixed(2)}s</span>
                    <span>Success Rate: {((results.total_cracked / results.results.length) * 100).toFixed(1)}%</span>
                  </div>
                </div>

                {/* Results Table */}
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-gray-700">
                        <th className="text-left py-2">Hash</th>
                        <th className="text-left py-2">Type</th>
                        <th className="text-left py-2">Status</th>
                        <th className="text-left py-2">Plaintext</th>
                        <th className="text-left py-2">Strength</th>
                        <th className="text-left py-2">Time</th>
                        <th className="text-left py-2">Attempts</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.results.map((result, index) => (
                        <tr key={index} className="border-b border-gray-700">
                          <td className="py-2 font-mono text-xs">
                            {result.hash_value.substring(0, 16)}...
                          </td>
                          <td className="py-2">{result.hash_type}</td>
                          <td className="py-2">
                            <span className={`px-2 py-1 rounded text-xs ${
                              result.cracked ? "bg-green-900 text-green-200" : "bg-red-900 text-red-200"
                            }`}>
                              {result.cracked ? "Cracked" : "Not Cracked"}
                            </span>
                          </td>
                          <td className="py-2 font-mono">
                            {result.plaintext || "N/A"}
                          </td>
                          <td className="py-2">
                            <span className={`font-medium ${getStrengthColor(result.strength_score)}`}>
                              {result.strength_score}/10 ({getStrengthLabel(result.strength_score)})
                            </span>
                          </td>
                          <td className="py-2">{result.time_taken.toFixed(3)}s</td>
                          <td className="py-2">{result.attempts}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* History Tab */}
        {activeTab === "history" && (
          <div className="space-y-6">
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-xl font-bold mb-4">Analysis History</h2>
              {history.length === 0 ? (
                <p className="text-gray-400">No analysis history available.</p>
              ) : (
                <div className="space-y-4">
                  {history.map((item, index) => (
                    <div key={index} className="bg-gray-700 rounded-lg p-4">
                      <div className="flex justify-between items-start mb-2">
                        <div>
                          <h4 className="font-semibold">
                            Analysis #{history.length - index}
                          </h4>
                          <p className="text-sm text-gray-400">
                            {new Date(item.timestamp).toLocaleString()}
                          </p>
                        </div>
                        <div className="text-right">
                          <p className="text-sm">
                            {item.total_cracked}/{item.results.length} cracked
                          </p>
                          <p className="text-sm text-gray-400">
                            {item.total_time.toFixed(2)}s
                          </p>
                        </div>
                      </div>
                      <p className="text-sm text-gray-300">{item.summary}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Stats Tab */}
        {activeTab === "stats" && (
          <div className="space-y-6">
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-xl font-bold mb-4">Statistics Dashboard</h2>
              {stats && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                  <div className="bg-gray-700 rounded-lg p-4">
                    <h3 className="text-sm font-medium text-gray-400">Total Analyses</h3>
                    <p className="text-2xl font-bold">{stats.total_analyses}</p>
                  </div>
                  <div className="bg-gray-700 rounded-lg p-4">
                    <h3 className="text-sm font-medium text-gray-400">Hashes Analyzed</h3>
                    <p className="text-2xl font-bold">{stats.total_hashes_analyzed}</p>
                  </div>
                  <div className="bg-gray-700 rounded-lg p-4">
                    <h3 className="text-sm font-medium text-gray-400">Avg Crack Rate</h3>
                    <p className="text-2xl font-bold">{stats.average_crack_rate}%</p>
                  </div>
                  <div className="bg-gray-700 rounded-lg p-4">
                    <h3 className="text-sm font-medium text-gray-400">Hash Types</h3>
                    <p className="text-2xl font-bold">{stats.most_common_hash_types.length}</p>
                  </div>
                </div>
              )}
              
              {stats && stats.most_common_hash_types.length > 0 && (
                <div className="mt-6">
                  <h3 className="text-lg font-semibold mb-3">Most Common Hash Types</h3>
                  <div className="bg-gray-700 rounded-lg p-4">
                    {stats.most_common_hash_types.map(([type, count], index) => (
                      <div key={index} className="flex justify-between items-center py-2">
                        <span>{type}</span>
                        <span className="text-blue-400">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              
              {stats && stats.weakest_passwords.length > 0 && (
                <div className="mt-6">
                  <h3 className="text-lg font-semibold mb-3">Most Common Weak Passwords</h3>
                  <div className="bg-gray-700 rounded-lg p-4">
                    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
                      {stats.weakest_passwords.map((password, index) => (
                        <span key={index} className="bg-red-900 text-red-200 px-2 py-1 rounded text-sm font-mono">
                          {password}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;