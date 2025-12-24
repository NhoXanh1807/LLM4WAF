import React, { useState, useEffect } from 'react';
import BypassedDataTable from './BypassedDataTable';
import { Services } from './services';

function App() {
  const [activeTab, setActiveTab] = useState('Attack');
  const [wafInfo, setWafInfo] = useState(null);
  const [payloads, setPayloads] = useState([]);
  const [domain, setDomain] = useState('');
  const [attackType, setAttackType] = useState('xss_dom');
  const [numPayloads, setNumPayloads] = useState(5);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [defenseRules, setDefenseRules] = useState([]);
  const [rawResponse, setRawResponse] = useState(null);
  const [showRaw, setShowRaw] = useState(false);
  const [isRetesting, setIsRetesting] = useState(false);
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem('darkMode');
    return saved ? JSON.parse(saved) : false;
  });

  useEffect(() => {
    localStorage.setItem('darkMode', JSON.stringify(darkMode));
    if (darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [darkMode]);

  // Helper download
  const handleDownload = (filename) => {
    let data = null;
    if (filename === "waf")
      data = wafInfo;
    else if (filename === "payloads")
      data = payloads;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename + '.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className={`min-h-screen transition-colors duration-300 ${darkMode ? 'bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900' : 'bg-gradient-to-br from-blue-50 via-white to-purple-50'}`}>
      {/* Header */}
      <div className="container mx-auto px-4 py-6">
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-4">
            <img
              src="/llmshield.png"
              alt="LLMShield Logo"
              className="w-16 h-16 rounded-2xl shadow-2xl ring-4 ring-red-500/30 hover:ring-red-500/50 transition-all duration-300"
            />
            <div>
              <h1 className={`text-3xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>LLMShield</h1>
              <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>AI-Powered WAF Testing Platform</p>
            </div>
          </div>

          {/* Dark Mode Toggle */}
          <button
            onClick={() => setDarkMode(!darkMode)}
            className={`p-3 rounded-xl transition-all duration-300 ${darkMode ? 'bg-gray-700 hover:bg-gray-600' : 'bg-white hover:bg-gray-100'} shadow-lg`}
            title={darkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
          >
            <span className="text-2xl">{darkMode ? '☀️' : '🌙'}</span>
          </button>
        </div>

        {/* Tabs */}
        <div className="flex gap-4 mb-6">
          <button
            className={`flex-1 py-4 px-6 rounded-xl font-bold text-lg transition-all duration-300 ${
              activeTab === 'Attack'
                ? darkMode
                  ? 'bg-gradient-to-r from-red-600 to-orange-600 text-white shadow-lg shadow-red-500/50'
                  : 'bg-gradient-to-r from-red-500 to-pink-600 text-white shadow-lg shadow-red-500/50'
                : darkMode
                ? 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                : 'bg-white text-gray-600 hover:bg-gray-50 shadow'
            }`}
            onClick={() => setActiveTab('Attack')}
          >
            🎯 Red Team
          </button>
          <button
            className={`flex-1 py-4 px-6 rounded-xl font-bold text-lg transition-all duration-300 ${
              activeTab === 'Defend'
                ? darkMode
                  ? 'bg-gradient-to-r from-blue-600 to-cyan-600 text-white shadow-lg shadow-blue-500/50'
                  : 'bg-gradient-to-r from-blue-500 to-cyan-600 text-white shadow-lg shadow-blue-500/50'
                : darkMode
                ? 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                : 'bg-white text-gray-600 hover:bg-gray-50 shadow'
            }`}
            onClick={() => setActiveTab('Defend')}
          >
            🛡️ Blue Team
          </button>
        </div>
      </div>
      {/* Content */}
      <div className="container mx-auto px-4 pb-8">
        <div className={`p-8 rounded-2xl shadow-2xl transition-colors duration-300 ${darkMode ? 'bg-gray-800/50 backdrop-blur-sm' : 'bg-white/80 backdrop-blur-sm'}`}>
        {activeTab === 'Attack' && (
          <>
            {/* Attack Form */}
            <form className="flex flex-wrap items-center gap-4 mb-6" onSubmit={async (e) => {
              e.preventDefault();
              setIsSubmitting(true);
              try {
                const res = await Services.attack(domain, attackType, numPayloads);
                const data = res.ok ? await res.json() : null;
                console.log(data);
                setWafInfo(data?.waf_info);
                setPayloads(data?.payloads || []);
                setDefenseRules(data?.defense_rules || []);
                setRawResponse(data);

                // Auto switch to Defend tab if any payload bypassed
                const hasBypassed = data?.payloads?.some(p => p.bypassed === true);
                if (hasBypassed) {
                  setActiveTab('Defend');
                }
              } finally {
                setIsSubmitting(false);
              }
            }}>
              <select
                className={`px-4 py-3 rounded-lg font-medium transition-all duration-200 ${
                  darkMode
                    ? 'bg-gray-700 text-white border-gray-600 hover:bg-gray-600'
                    : 'bg-white text-gray-900 border-gray-300 hover:border-red-400'
                } border-2 focus:outline-none focus:ring-2 focus:ring-red-500`}
                value={attackType}
                onChange={e => setAttackType(e.target.value)}
              >
                <option value="xss_dom">XSS DOM-Based</option>
                <option value="xss_reflected">XSS Reflected</option>
                <option value="xss_stored">XSS Stored</option>
                <option value="sql_injection">SQL Injection</option>
                <option value="sql_injection_blind">Blind SQL Injection</option>
              </select>
              <input
                type="text"
                className={`flex-1 px-4 py-3 rounded-lg font-medium transition-all duration-200 ${
                  darkMode
                    ? 'bg-gray-700 text-white border-gray-600 placeholder-gray-400'
                    : 'bg-white text-gray-900 border-gray-300 placeholder-gray-500'
                } border-2 focus:outline-none focus:ring-2 focus:ring-red-500`}
                placeholder="Target Domain (e.g., modsec.llmshield.click)"
                value={domain}
                onChange={e => setDomain(e.target.value)}
                required
              />
              <input
                type="number"
                className={`w-28 px-4 py-3 rounded-lg font-medium text-center transition-all duration-200 ${
                  darkMode
                    ? 'bg-gray-700 text-white border-gray-600'
                    : 'bg-white text-gray-900 border-gray-300'
                } border-2 focus:outline-none focus:ring-2 focus:ring-red-500`}
                placeholder="#"
                min="1"
                max="20"
                value={numPayloads}
                onChange={e => setNumPayloads(parseInt(e.target.value) || 5)}
                title="Number of payloads (1-20)"
              />
              <button
                type="submit"
                disabled={isSubmitting}
                className="px-8 py-3 rounded-lg font-bold text-white bg-gradient-to-r from-red-500 to-pink-600 hover:from-red-600 hover:to-pink-700 disabled:from-gray-400 disabled:to-gray-500 shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed"
              >
                {isSubmitting ? '🔄 Attacking...' : '🚀 Launch Attack'}
              </button>
            </form>
            {/* Download Buttons */}
            <div className="flex gap-3 mb-6">
              <button
                className="px-5 py-2 rounded-lg font-semibold text-white bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 disabled:from-gray-400 disabled:to-gray-500 shadow hover:shadow-lg transition-all duration-200 disabled:cursor-not-allowed"
                disabled={!wafInfo}
                onClick={() => handleDownload('waf')}
              >
                📥 WAF Info
              </button>
              <button
                className="px-5 py-2 rounded-lg font-semibold text-white bg-gradient-to-r from-orange-500 to-red-600 hover:from-orange-600 hover:to-red-700 disabled:from-gray-400 disabled:to-gray-500 shadow hover:shadow-lg transition-all duration-200 disabled:cursor-not-allowed"
                disabled={!payloads || !payloads.length}
                onClick={() => handleDownload('payloads')}
              >
                📥 Payloads
              </button>
            </div>
            {/* Results Table */}
            <BypassedDataTable
              wafInfo={wafInfo}
              payloads={payloads}
              darkMode={darkMode}
            />
            {/* Toggle Raw Response */}
            <div className="mt-6 flex flex-col items-start">
              <button
                className={`px-4 py-2 rounded-lg font-semibold text-sm transition-all duration-200 ${
                  darkMode
                    ? 'bg-gray-700 hover:bg-gray-600 text-gray-300'
                    : 'bg-gray-200 hover:bg-gray-300 text-gray-700'
                }`}
                onClick={() => setShowRaw(!showRaw)}
                type="button"
              >
                {showRaw ? '🙈 Hide Raw Response' : '👁️ Show Raw Response'}
              </button>
              {showRaw && rawResponse && (
                <textarea
                  className={`w-full h-40 mt-3 border-2 rounded-lg p-4 text-xs font-mono transition-colors duration-200 ${
                    darkMode
                      ? 'bg-gray-900 border-gray-700 text-green-400'
                      : 'bg-gray-50 border-gray-300 text-gray-800'
                  }`}
                  value={typeof rawResponse === 'string' ? rawResponse : JSON.stringify(rawResponse, null, 2)}
                  readOnly
                  placeholder="Raw API response will be displayed here..."
                />
              )}
            </div>
          </>
        )}
        {activeTab === 'Defend' && (
          <>
            {/* Bypassed Payloads Section */}
            <div className="mb-8">
              <div className="flex items-center justify-between mb-4">
                <h2 className={`text-2xl font-bold ${darkMode ? 'text-red-400' : 'text-red-600'}`}>
                  ⚠️ Bypassed Payloads
                </h2>
                {payloads.filter(p => p.bypassed === true).length > 0 && (
                  <button
                    onClick={async () => {
                      setIsRetesting(true);
                      try {
                        const bypassedPayloads = payloads.filter(p => p.bypassed === true);
                        const res = await Services.retest(bypassedPayloads);
                        const data = res.ok ? await res.json() : null;

                        if (data && data.results) {
                          // Update payloads with retest results
                          const updatedPayloads = payloads.map(p => {
                            const retestResult = data.results.find(r => r.payload === p.payload);
                            return retestResult ? { ...p, bypassed: retestResult.bypassed, status_code: retestResult.status_code } : p;
                          });
                          setPayloads(updatedPayloads);
                        }
                      } finally {
                        setIsRetesting(false);
                      }
                    }}
                    disabled={isRetesting}
                    className="px-6 py-2 rounded-lg font-semibold text-white bg-gradient-to-r from-orange-500 to-red-600 hover:from-orange-600 hover:to-red-700 disabled:from-gray-400 disabled:to-gray-500 shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed"
                  >
                    {isRetesting ? '🔄 Retesting...' : '🔄 Retest Bypassed'}
                  </button>
                )}
              </div>
              <BypassedDataTable
                wafInfo={wafInfo}
                payloads={payloads.filter(p => p.bypassed === true)}
                darkMode={darkMode}
              />
            </div>

            {/* Defense Rules */}
            {defenseRules && defenseRules.length > 0 ? (
              <div className="mt-8">
                <h2 className={`text-2xl font-bold mb-4 ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>
                  🛡️ Defense Rules Generated
                </h2>
                <div className="overflow-x-auto rounded-xl border-2 ${darkMode ? 'border-gray-700' : 'border-gray-200'}">
                  <table className="min-w-full">
                    <thead>
                      <tr className={darkMode ? 'bg-blue-900/30' : 'bg-blue-100'}>
                        <th className={`text-left font-bold p-4 ${darkMode ? 'text-blue-300' : 'text-blue-900'}`}>#</th>
                        <th className={`text-left font-bold p-4 ${darkMode ? 'text-blue-300' : 'text-blue-900'}`}>ModSecurity Rule</th>
                        <th className={`text-left font-bold p-4 ${darkMode ? 'text-blue-300' : 'text-blue-900'}`}>Implementation Guide</th>
                      </tr>
                    </thead>
                    <tbody>
                      {defenseRules.map((item, idx) => (
                        <tr key={idx} className={idx % 2 === 0 ? (darkMode ? 'bg-gray-800/30' : 'bg-white') : (darkMode ? 'bg-gray-800/50' : 'bg-gray-50')}>
                          <td className={`align-top p-4 text-center font-bold ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>{idx + 1}</td>
                          <td className="align-top p-4 w-1/2">
                            <pre className={`whitespace-pre-wrap text-xs font-mono p-3 rounded-lg ${darkMode ? 'bg-gray-900 text-green-400' : 'bg-gray-100 text-gray-800'}`}>{item.rule}</pre>
                          </td>
                          <td className={`align-top p-4 w-1/2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                            <p className="text-sm leading-relaxed">{item.instructions}</p>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <div className={`text-center py-12 rounded-xl ${darkMode ? 'bg-green-900/20 border-2 border-green-700' : 'bg-green-50 border-2 border-green-200'}`}>
                <p className={`text-xl font-semibold ${darkMode ? 'text-green-400' : 'text-green-700'}`}>
                  ✅ No bypassed payloads detected. Your WAF is secure!
                </p>
              </div>
            )}

            {/* Toggle Raw Response */}
            <div className="mt-6 flex flex-col items-start">
              <button
                className={`px-4 py-2 rounded-lg font-semibold text-sm transition-all duration-200 ${
                  darkMode
                    ? 'bg-gray-700 hover:bg-gray-600 text-gray-300'
                    : 'bg-gray-200 hover:bg-gray-300 text-gray-700'
                }`}
                onClick={() => setShowRaw(!showRaw)}
                type="button"
              >
                {showRaw ? '🙈 Hide Raw Response' : '👁️ Show Raw Response'}
              </button>
              {showRaw && rawResponse && (
                <textarea
                  className={`w-full h-40 mt-3 border-2 rounded-lg p-4 text-xs font-mono transition-colors duration-200 ${
                    darkMode
                      ? 'bg-gray-900 border-gray-700 text-green-400'
                      : 'bg-gray-50 border-gray-300 text-gray-800'
                  }`}
                  value={typeof rawResponse === 'string' ? rawResponse : JSON.stringify(rawResponse, null, 2)}
                  readOnly
                  placeholder="Raw API response will be displayed here..."
                />
              )}
            </div>
          </>
        )}
        </div>
      </div>
    </div>
  );
}

export default App;
