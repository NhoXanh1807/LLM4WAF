
import React, { useEffect, useState } from 'react';
import { Services } from '../services';
import PayloadResultsTable from './PayloadResultsTable';


const TabDefend = ({ 
    wafName, 
    attackResults, 
    darkMode, 
    setError, 
    setAttackResults, 
    domain, 
    isAutoDefend, 
    setIsAutoDefend,
    defenseRules,
    setDefenseRules,
    loading,
    handleDefend,
    rawResponse,
    existingRules,
    setExistingRules,
}) => {
    
    const [loadingRetest, setLoadingRetest] = useState(false);
    const [showRaw, setShowRaw] = useState(false);

    // Handler to retest attack DVWA (update attackResults in-place)
    const handleRetestAttack = async () => {
        if (!attackResults || attackResults.length === 0) return;
        setAttackResults(prev => prev.map(p => ({ ...p, bypassed: null, status_code: null, is_harmful: null }))); // Reset bypassed/status_code before retest
        setLoadingRetest(true);
        setError && setError(null);
        try {
            const res = await Services.apiTestAttack(
                domain,
                attackResults
            );
            const data = await res.json();
            if (!res.ok) {
                setError && setError(data?.error || `Server error: ${res.status}`);
                setLoadingRetest(false);
                return;
            }
            // Update attackResults in-place with new bypassed/status_code
            if (setAttackResults) {
                setAttackResults(prev => prev.map(p => {
                    const found = (data?.payloads || []).find(r => r.payload === p.payload);
                    if (found) {
                        return { ...p, is_bypassed: found.is_bypassed, status_code: found.status_code, is_harmful: found.is_harmful };
                    }
                    return p;
                }));
            }
        } catch (err) {
            setError && setError(err.message || 'Failed to connect to backend');
        } finally {
            setLoadingRetest(false);
        }
    };

    return (
        <div className="space-y-10">
            {/* Bypassed Payloads Section */}
            <div className="mb-8">
                {/* Info: Domain & WAF Name */}
                <div className="mb-4 flex flex-wrap gap-4 items-center">
                    <span className={`px-4 py-2 rounded-lg font-semibold text-base ${darkMode ? 'bg-gray-800 text-cyan-300' : 'bg-gray-100 text-cyan-700'}`}>
                        🌐 Domain: <span className="font-mono">{domain || 'N/A'}</span>
                    </span>
                    <span className={`px-4 py-2 rounded-lg font-semibold text-base ${darkMode ? 'bg-gray-800 text-blue-300' : 'bg-gray-100 text-blue-700'}`}>
                        🛡️ WAF: <span className="font-mono">{wafName || 'N/A'}</span>
                    </span>
                </div>
                <PayloadResultsTable
                    wafName={wafName}
                    payloads={attackResults.filter(p => p.is_bypassed === true)}
                    darkMode={darkMode}
                />
            </div>

            {/* Existing Rules Input Section */}
            <div className="mb-8">
                <label className="block font-semibold mb-2 text-base text-blue-700 dark:text-blue-300">Existing WAF Rules (optional)</label>
                <div className="flex flex-col md:flex-row gap-4 items-start mb-2">
                    <textarea
                        className={`w-full md:w-2/3 min-h-[80px] max-h-60 p-3 rounded-lg border-2 font-mono text-sm transition-colors duration-200 ${darkMode ? 'bg-gray-900 border-gray-700 text-green-300' : 'bg-gray-50 border-gray-300 text-gray-800'}`}
                        value={existingRules}
                        onChange={e => setExistingRules(e.target.value)}
                        placeholder="Paste existing rules here (plain text, JSON, or one rule per line)"
                    />
                    <label className="px-4 py-2 rounded-lg font-semibold text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 cursor-pointer hover:bg-gray-300 dark:hover:bg-gray-600 transition-all duration-200 mt-2 md:mt-0">
                        📤 Upload
                        <input
                            type="file"
                            accept=".txt,.json,application/json,text/plain"
                            className="hidden"
                            onChange={e => {
                                const file = e.target.files[0];
                                if (!file) return;
                                const reader = new FileReader();
                                reader.onload = evt => {
                                    setExistingRules(evt.target.result);
                                };
                                reader.readAsText(file);
                            }}
                        />
                    </label>
                </div>
                <div className="text-xs text-gray-500 dark:text-gray-400">Supported: plain text (one rule per line), JSON array, or list of objects with <code>rule</code> key.</div>
            </div>



            {/* Defense Button */}
            <div className="flex items-center gap-4 mb-8 flex-wrap">
                <button
                    className="px-8 py-3 rounded-xl font-bold text-white bg-gradient-to-r from-blue-500 to-cyan-600 hover:from-blue-600 hover:to-cyan-700 disabled:from-gray-400 disabled:to-gray-500 shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed"
                    onClick={handleDefend}
                    disabled={loading || !attackResults || attackResults.length === 0}
                    type="button"
                >
                    {loading ? '🔄 Generating Defense...' : '🛡️ Generate Defense Rules'}
                </button>
                <button
                    className="px-8 py-3 rounded-xl font-bold text-white bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 disabled:from-gray-400 disabled:to-gray-500 shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed"
                    onClick={handleRetestAttack}
                    disabled={loadingRetest || !attackResults || attackResults.length === 0}
                    type="button"
                >
                    {loadingRetest ? '🔄 Retesting...' : '🧪 Retest Attack DVWA'}
                </button>
                {defenseRules.length > 0 && (
                    <span className={`text-sm font-semibold px-3 py-1 rounded-full ${darkMode ? 'bg-blue-900/40 text-blue-300' : 'bg-blue-100 text-blue-700'}`}>
                        {defenseRules.length} rule{defenseRules.length !== 1 ? 's' : ''}
                    </span>
                )}
            </div>

            {/* Defense Rules Table */}
            {defenseRules.length > 0 && (
                <div className="mt-8">
                    <div className="flex items-center justify-between mb-4">
                        <h2 className={`text-2xl font-bold ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>🛡️ Defense Rules Generated</h2>
                    </div>
                    <div className={`overflow-x-auto rounded-xl border-2 ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
                        <table className="min-w-full">
                            <thead>
                                <tr className={darkMode ? 'bg-blue-900/30' : 'bg-blue-100'}>
                                    <th className={`text-left font-bold p-4 w-8 ${darkMode ? 'text-blue-300' : 'text-blue-900'}`}>#</th>
                                    <th className={`text-left font-bold p-4 w-24 ${darkMode ? 'text-blue-300' : 'text-blue-900'}`}>WAF Type</th>
                                    <th className={`text-left font-bold p-4 ${darkMode ? 'text-blue-300' : 'text-blue-900'}`}>WAF Rule</th>
                                    <th className={`text-left font-bold p-4 ${darkMode ? 'text-blue-300' : 'text-blue-900'}`}>Implementation Guide</th>
                                </tr>
                            </thead>
                            <tbody>
                                {defenseRules.map((item, idx) => (
                                    <tr key={idx} className={idx % 2 === 0 ? (darkMode ? 'bg-gray-800/30' : 'bg-white') : (darkMode ? 'bg-gray-800/50' : 'bg-gray-50')}>
                                        <td className={`align-top p-4 text-center font-bold ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>{idx + 1}</td>
                                        <td className="align-top p-4">
                                            <span className={`px-2 py-1 rounded text-xs font-semibold uppercase ${darkMode ? 'bg-cyan-900/30 text-cyan-400' : 'bg-cyan-100 text-cyan-700'}`}>
                                                {item.waf_type || 'modsecurity'}
                                            </span>
                                            {item.is_valid === false && (
                                                <span className="ml-1 px-2 py-1 rounded text-xs font-semibold bg-red-500 text-white">invalid</span>
                                            )}
                                        </td>
                                        <td className="align-top p-4 w-1/2">
                                            <pre className={`whitespace-pre-wrap text-xs font-mono p-3 rounded-lg ${darkMode ? 'bg-gray-900 text-green-400' : 'bg-gray-100 text-gray-800'}`}>{item.rule}</pre>
                                            {item.refinement_notes && (
                                                <p className={`mt-2 text-xs italic ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                                                    ✨ {item.refinement_notes}
                                                </p>
                                            )}
                                        </td>
                                        <td className={`align-top p-4 w-1/3 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                            <p className="text-sm leading-relaxed">{item.instructions}</p>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* Toggle Raw Response */}
            <div className="mt-6 flex flex-col items-start">
                <button
                    className={`px-4 py-2 rounded-lg font-semibold text-sm transition-all duration-200 ${darkMode
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
                        className={`w-full h-40 mt-3 border-2 rounded-lg p-4 text-xs font-mono transition-colors duration-200 ${darkMode
                            ? 'bg-gray-900 border-gray-700 text-green-400'
                            : 'bg-gray-50 border-gray-300 text-gray-800'
                            }`}
                        value={typeof rawResponse === 'string' ? rawResponse : JSON.stringify(rawResponse, null, 2)}
                        readOnly
                        placeholder="Raw API response will be displayed here..."
                    />
                )}
            </div>
        </div>
    );
}
export default TabDefend;