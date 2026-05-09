import React, { useState, useEffect } from 'react';
import TabAttack from './components/TabAttack';
import TabDefend from './components/TabDefend';
import { Services } from './services';

const normalizeRagSource = (source, index) => {
  const fallbackTitle = `Source ${index + 1}`;
  const content = typeof source === 'string'
    ? source
    : String(
      source?.content
      ?? source?.text
      ?? source?.page_content
      ?? source?.chunk
      ?? source?.rule
      ?? ''
    );

  return {
    id: source?.id ?? `${source?.path || source?.file_name || fallbackTitle}-${index}`,
    title: source?.title || source?.file_name || source?.filename || source?.path || fallbackTitle,
    waf_name: source?.waf_name || source?.waf || '',
    attack_type: source?.attack_type || source?.attack || '',
    path: source?.path || source?.file_path || '',
    section: source?.section || source?.category || '',
    content,
    raw: source,
  };
};

const buildRagContextFromSources = (sources = [], fallback = '') => {
  const normalized = Array.isArray(sources) ? sources : [];
  const parts = normalized
    .map(source => String(source?.content || '').trim())
    .filter(Boolean);

  return parts.length > 0 ? parts.join('\n\n---\n\n') : fallback;
};

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

  // step 4 - defend (multi-step)
  const [defenseRules, setDefenseRules] = useState([]);
  const [rawResponse, setRawResponse] = useState(null);
  const [existingRules, setExistingRules] = useState('');
  const [existingRuleFiles, setExistingRuleFiles] = useState([]);
  const [llmProvider, setLlmProvider] = useState('claude');

  // Defend step-by-step state
  const [defendLoading, setDefendLoading] = useState({
    clustering: false,
    rag: false,
    generate: false,
    validate: false,
    retry: false,
    refine: false,
    auto: false,
  });
  const [defendError, setDefendError] = useState({});
  const [clusters, setClusters] = useState([]);
  const [bypassedPayloads, setBypassedPayloads] = useState([]);
  const [ragResult, setRagResult] = useState(null);
  const [ragSources, setRagSources] = useState([]);
  const [ragContext, setRagContext] = useState('');
  const [generatedRules, setGeneratedRules] = useState([]);
  const [generationPrompt, setGenerationPrompt] = useState('');
  const [validRules, setValidRules] = useState([]);
  const [invalidRules, setInvalidRules] = useState([]);
  const [retriedRules, setRetriedRules] = useState([]);
  const [finalRules, setFinalRules] = useState([]);
  const [defendStats, setDefendStats] = useState({});

  const [loading, setLoading] = useState(false); // for backward compatibility

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

  // DEFEND HANDLERS (step-by-step)
  const getExistingRulesArray = () => [
    existingRules,
    ...existingRuleFiles.map(file => file.content),
  ].map(rule => rule.trim()).filter(rule => rule.length > 0);

  const getCurrentAttackType = (payloads = attackResults) => {
    const derivedAttackType = (payloads || []).find(item => item?.attack_type)?.attack_type;
    return derivedAttackType || attackType || '';
  };

  const handleDefendClustering = async (payloadsOverride = attackResults) => {
    setDefendLoading(l => ({ ...l, clustering: true }));
    setDefendError(e => ({ ...e, clustering: null }));
    try {
      const attack_type = getCurrentAttackType(payloadsOverride);
      const res = await Services.apiDefendClustering(attack_type, payloadsOverride);
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || 'Clustering failed');
      setClusters(data.clusters || []);
      setBypassedPayloads(data.bypassed_payloads || []);
      setRagResult(null);
      setRagSources([]);
      setRagContext('');
      setGeneratedRules([]);
      setValidRules([]);
      setInvalidRules([]);
      setRetriedRules([]);
      setFinalRules([]);
      setDefenseRules([]);
      setDefendStats(s => ({ ...s, clustering: data.stats }));
      return data;
    } catch (err) {
      setDefendError(e => ({ ...e, clustering: err.message }));
      setClusters([]);
      setBypassedPayloads([]);
      throw err;
    } finally {
      setDefendLoading(l => ({ ...l, clustering: false }));
    }
  };

  const handleDefendRag = async (payloadsOverride = attackResults) => {
    setDefendLoading(l => ({ ...l, rag: true }));
    setDefendError(e => ({ ...e, rag: null }));
    try {
      const res = await Services.apiDefendRagRetrieve(wafName, null, payloadsOverride);
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || 'RAG retrieve failed');
      const normalizedSources = (data.rag_sources || []).map((source, index) => normalizeRagSource(source, index));
      const nextRagContext = buildRagContextFromSources(normalizedSources, data.rag_context || '');
      setRagResult(data.rag_result || null);
      setRagSources(normalizedSources);
      setRagContext(nextRagContext);
      setGeneratedRules([]);
      setValidRules([]);
      setInvalidRules([]);
      setRetriedRules([]);
      setFinalRules([]);
      setDefenseRules([]);
      setDefendStats(s => ({ ...s, rag: data.stats }));
      return {
        ...data,
        rag_sources: normalizedSources,
        rag_context: nextRagContext,
      };
    } catch (err) {
      setDefendError(e => ({ ...e, rag: err.message }));
      setRagResult(null);
      setRagSources([]);
      setRagContext('');
      throw err;
    } finally {
      setDefendLoading(l => ({ ...l, rag: false }));
    }
  };

  const handleDefendGenerateRules = async (
    clustersOverride = clusters,
    ragSourcesOverride = ragSources,
    ragContextOverride = ragContext,
  ) => {
    setDefendLoading(l => ({ ...l, generate: true }));
    setDefendError(e => ({ ...e, generate: null }));
    try {
      const nextRagContext = buildRagContextFromSources(ragSourcesOverride, ragContextOverride);
      const res = await Services.apiDefendGenerateRules(wafName, clustersOverride, nextRagContext);
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || 'Generate rules failed');
      setGeneratedRules(data.generated_rules || []);
      setGenerationPrompt(data.generation_prompt || '');
      setValidRules([]);
      setInvalidRules([]);
      setRetriedRules([]);
      setFinalRules([]);
      setDefenseRules([]);
      setDefendStats(s => ({ ...s, generate: data.stats }));
      return data;
    } catch (err) {
      setDefendError(e => ({ ...e, generate: err.message }));
      setGeneratedRules([]);
      setGenerationPrompt('');
      throw err;
    } finally {
      setDefendLoading(l => ({ ...l, generate: false }));
    }
  };

  const handleDefendValidateRules = async (rulesOverride = generatedRules) => {
    setDefendLoading(l => ({ ...l, validate: true }));
    setDefendError(e => ({ ...e, validate: null }));
    try {
      const res = await Services.apiDefendValidateRules(rulesOverride);
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || 'Validate rules failed');
      setValidRules(data.valid_rules || []);
      setInvalidRules(data.invalid_rules || []);
      setRetriedRules([]);
      setFinalRules([]);
      setDefenseRules([]);
      setDefendStats(s => ({ ...s, validate: data.stats }));
      return data;
    } catch (err) {
      setDefendError(e => ({ ...e, validate: err.message }));
      setValidRules([]);
      setInvalidRules([]);
      throw err;
    } finally {
      setDefendLoading(l => ({ ...l, validate: false }));
    }
  };

  const handleDefendRetryInvalidRules = async (invalidRulesOverride = invalidRules) => {
    setDefendLoading(l => ({ ...l, retry: true }));
    setDefendError(e => ({ ...e, retry: null }));
    try {
      const res = await Services.apiDefendRetryInvalidRules(wafName, invalidRulesOverride);
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || 'Retry invalid rules failed');
      setRetriedRules(data.retried_rules || []);
      setFinalRules([]);
      setDefenseRules([]);
      setDefendStats(s => ({ ...s, retry: data.stats }));
      return data;
    } catch (err) {
      setDefendError(e => ({ ...e, retry: err.message }));
      setRetriedRules([]);
      throw err;
    } finally {
      setDefendLoading(l => ({ ...l, retry: false }));
    }
  };

  const handleDefendRefineRules = async (
    validRulesOverride = validRules,
    retriedRulesOverride = retriedRules,
  ) => {
    setDefendLoading(l => ({ ...l, refine: true }));
    setDefendError(e => ({ ...e, refine: null }));
    try {
      const res = await Services.apiDefendRefineRules(
        wafName,
        [...validRulesOverride, ...retriedRulesOverride],
        getExistingRulesArray(),
      );
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || 'Refine rules failed');
      setFinalRules(data.final_rules || []);
      setDefendStats(s => ({ ...s, refine: data.stats }));
      setDefenseRules(data.final_rules || []);
      return data;
    } catch (err) {
      setDefendError(e => ({ ...e, refine: err.message }));
      setFinalRules([]);
      setDefenseRules([]);
      throw err;
    } finally {
      setDefendLoading(l => ({ ...l, refine: false }));
    }
  };

  // AUTO DEFEND ALL STEPS
  const handleAutoDefend = async () => {
    setDefendLoading(l => ({ ...l, auto: true }));
    setDefendError(e => ({ ...e, auto: null }));
    try {
      const clusteringData = await handleDefendClustering(attackResults);
      const ragData = await handleDefendRag(attackResults);
      const generateData = await handleDefendGenerateRules(
        clusteringData?.clusters || [],
        ragData?.rag_sources || [],
        ragData?.rag_context || '',
      );
      const validateData = await handleDefendValidateRules(generateData?.generated_rules || []);
      let retriedData = { retried_rules: [] };
      if ((validateData?.invalid_rules || []).length > 0) {
        retriedData = await handleDefendRetryInvalidRules(validateData.invalid_rules);
      }
      await handleDefendRefineRules(validateData?.valid_rules || [], retriedData?.retried_rules || []);
    } catch (err) {
      setDefendError(e => ({ ...e, auto: err.message }));
    } finally {
      setDefendLoading(l => ({ ...l, auto: false }));
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
            handleDefend={handleAutoDefend}
          />}
          {activeTab === 'Defend' && <TabDefend
            domain={domain}
            wafName={wafName}
            attackResults={attackResults}
            setAttackResults={setAttackResults}
            darkMode={darkMode}
            defenseRules={defenseRules}
            loading={loading}
            // defend step-by-step state/handlers
            defendLoading={defendLoading}
            defendError={defendError}
            clusters={clusters}
            bypassedPayloads={bypassedPayloads}
            ragResult={ragResult}
            ragSources={ragSources}
            ragContext={ragContext}
            generatedRules={generatedRules}
            generationPrompt={generationPrompt}
            validRules={validRules}
            invalidRules={invalidRules}
            retriedRules={retriedRules}
            finalRules={finalRules}
            defendStats={defendStats}
            setClusters={setClusters}
            setRagSources={setRagSources}
            setRagContext={setRagContext}
            setGeneratedRules={setGeneratedRules}
            setValidRules={setValidRules}
            setInvalidRules={setInvalidRules}
            setRetriedRules={setRetriedRules}
            handleDefendClustering={handleDefendClustering}
            handleDefendRag={handleDefendRag}
            handleDefendGenerateRules={handleDefendGenerateRules}
            handleDefendValidateRules={handleDefendValidateRules}
            handleDefendRetryInvalidRules={handleDefendRetryInvalidRules}
            handleDefendRefineRules={handleDefendRefineRules}
            handleAutoDefend={handleAutoDefend}
            existingRules={existingRules}
            setExistingRules={setExistingRules}
            existingRuleFiles={existingRuleFiles}
            setExistingRuleFiles={setExistingRuleFiles}
            llmProvider={llmProvider}
            setLlmProvider={setLlmProvider}
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
