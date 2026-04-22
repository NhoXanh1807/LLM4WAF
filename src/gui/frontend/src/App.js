import React, { useState, useEffect } from 'react';
import TabAttack from './components/TabAttack';
import TabDefend from './components/TabDefend';
import { Services } from './services';

function App() {
  const [activeTab, setActiveTab] = useState('Attack');
  const [error, setError] = useState(null);

  // step 1 - detect WAF
  const [domain, setDomain] = useState('');
  const [wafName, setWafName] = useState(null);

  // step 2 - generate payloads
  const [attackType, setAttackType] = useState('xss_dom');
  const [numPayloads, setNumPayloads] = useState(5);
  const [payloadsRandom, setPayloadsRandom] = useState([]);
  const [payloadsAdaptive, setPayloadsAdaptive] = useState([]);

  // step 3 - attack DVWA
  const [attackResults, setAttackResults] = useState([]);

  // step 4 - defend
  const [defenseRules, setDefenseRules] = useState([]);
  const [loading, setLoading] = useState(false);
  const [rawResponse, setRawResponse] = useState(null);
  const [existingRules, setExistingRules] = useState('');

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

  // Handler to call defense API
  const handleDefend = async () => {
    setLoading(true);
    setError && setError(null);
    try {
      // Prepare existingRules for backend: send as string (can be JSON, plain text, or array)
      let existingRulesToSend = existingRules && existingRules.trim() ? existingRules : null;
      const res = await Services.apiDefend(wafName, attackResults, 3, existingRulesToSend);
      const data = await res.json();
      setRawResponse(data);
      if (res.ok && data && data.final_rules) {
        setDefenseRules(data.final_rules);
      } else {
        setDefenseRules([]);
        setError && setError(data?.error || 'Failed to generate defense rules');
      }
    } catch (err) {
      setDefenseRules([]);
      setError && setError(err.message || 'Failed to connect to backend');
    } finally {
      setLoading(false);
    }
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

        {/* Tabs select */}
        <div className="flex gap-4 mb-6">
          <button
            className={`flex-1 py-4 px-6 rounded-xl font-bold text-lg transition-all duration-300 ${activeTab === 'Attack'
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
            className={`flex-1 py-4 px-6 rounded-xl font-bold text-lg transition-all duration-300 ${activeTab === 'Defend'
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
          {activeTab === 'Attack' && <TabAttack
            domain={domain}
            setDomain={setDomain}
            attackType={attackType}
            setAttackType={setAttackType}
            numPayloads={numPayloads}
            setNumPayloads={setNumPayloads}
            error={error}
            setError={setError}
            wafName={wafName}
            setWafName={setWafName}
            darkMode={darkMode}
            payloadsRandom={payloadsRandom}
            setPayloadsRandom={setPayloadsRandom}
            payloadsAdaptive={payloadsAdaptive}
            setPayloadsAdaptive={setPayloadsAdaptive}
            attackResults={attackResults}
            setAttackResults={setAttackResults}
            setActiveTab={setActiveTab}
            handleDefend={handleDefend}
          />}
          {activeTab === 'Defend' && <TabDefend
            domain={domain}
            wafName={wafName}
            attackResults={attackResults}
            setAttackResults={setAttackResults}
            darkMode={darkMode}
            setError={setError}
            defenseRules={defenseRules}
            loading={loading}
            handleDefend={handleDefend}
            rawResponse={rawResponse}
            existingRules={existingRules}
            setExistingRules={setExistingRules}
          />}

          {/* Error Popup Modal */}
          {error && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-40">
              <div className={`relative max-w-md w-full mx-4 p-8 rounded-2xl shadow-2xl border-2 ${darkMode ? 'bg-gray-900 border-red-700 text-red-300' : 'bg-white border-red-400 text-red-700'}`}>
                <button
                  className="absolute top-3 right-3 text-2xl font-bold px-2 py-1 rounded hover:bg-red-100 dark:hover:bg-red-900/30 transition-all"
                  onClick={() => setError(null)}
                  aria-label="Close error popup"
                  type="button"
                >
                  ×
                </button>
                <div className="flex items-center gap-3 mb-2">
                  <span className="text-3xl">⚠️</span>
                  <h3 className="font-bold text-xl">Đã xảy ra lỗi</h3>
                </div>
                <div className="mt-2 text-base break-words whitespace-pre-line">
                  {error}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
