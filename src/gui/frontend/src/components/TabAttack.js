
import React, { useState } from 'react';
import { Services } from '../services';
import PayloadResultsTable from './PayloadResultsTable';

const AttackTab = ({
    domain,
    setDomain,
    attackType,
    setAttackType,
    numPayloads,
    setNumPayloads,
    isSubmitting,
    setIsSubmitting,
    error,
    setError,
    wafName,
    setWafName,
    payloads,
    setPayloads,
    darkMode,
    payloadsRandom,
    setPayloadsRandom,
    payloadsAdaptive,
    setPayloadsAdaptive,
    attackResults,
    setAttackResults,
    setActiveTab,
}) => {
    // Per-button loading states
    const [loadingDetect, setLoadingDetect] = useState(false);
    const [loadingGenRandom, setLoadingGenRandom] = useState(false);
    const [loadingGenAdaptive, setLoadingGenAdaptive] = useState(false);
    const [loadingAttackRandom, setLoadingAttackRandom] = useState(false);
    const [loadingAttackAdaptive, setLoadingAttackAdaptive] = useState(false);

    // Step 1: Detect WAF
    const handleDetectWAFClick = async () => {
        setLoadingDetect(true);
        setError(null);
        try {
            const res = await Services.apiDetectWAF(domain);
            const data = await res.json();
            if (!res.ok) {
                setError(data?.error || `Server error: ${res.status}`);
                setWafName(null);
                return;
            }
            setWafName(data?.waf_name || '');
        } catch (err) {
            setError(err.message || 'Failed to connect to backend');
            setWafName(null);
        } finally {
            setLoadingDetect(false);
        }
    };


    // Step 2: Generate Random Payloads
    const handleGenerateRandomPayloadsClick = async () => {
        setLoadingGenRandom(true);
        setError(null);
        try {
            const res = await Services.apiGeneratePayloadRandom(wafName, attackType, numPayloads, []);
            const data = await res.json();
            if (!res.ok) {
                setError(data?.error || `Server error: ${res.status}`);
                setPayloadsRandom([]);
                return;
            }
            setPayloadsRandom(data?.payloads || []);
        } catch (err) {
            setError(err.message || 'Failed to connect to backend');
            setPayloadsRandom([]);
        } finally {
            setLoadingGenRandom(false);
        }
    };

    // Step 2.1: Generate Adaptive Payloads
    const handleGenerateAdaptivePayloadsClick = async () => {
        setLoadingGenAdaptive(true);
        setError(null);
        try {
            const res = await Services.apiGeneratePayloadAdaptive(wafName, attackType, numPayloads, payloadsRandom);
            const data = await res.json();
            if (!res.ok) {
                setError(data?.error || `Server error: ${res.status}`);
                setPayloadsAdaptive([]);
                return;
            }
            setPayloadsAdaptive(data?.payloads || []);
        } catch (err) {
            setError(err.message || 'Failed to connect to backend');
            setPayloadsAdaptive([]);
        } finally {
            setLoadingGenAdaptive(false);
        }
    };

    // General-purpose import/export handlers for payload arrays
    const handleImportPayloadsGeneric = (e, setPayloadsFn) => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (evt) => {
            try {
                const imported = JSON.parse(evt.target.result);
                setPayloadsFn(imported);
            } catch {
                setError('Invalid payloads file');
            }
        };
        reader.readAsText(file);
    };

    const handleExportPayloadsGeneric = (payloads, filename) => {
        const blob = new Blob([JSON.stringify(payloads, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    };

    // Step 3: Test Attack on DVWA for Random Payloads (update payloadsRandom in place)
    const handleTestAttackRandom = async () => {
        setLoadingAttackRandom(true);
        setError(null);
        try {
            const res = await Services.apiAttackDVWA(domain, payloadsRandom);
            const data = await res.json();
            if (!res.ok) {
                setError(data?.error || `Server error: ${res.status}`);
                return;
            }
            setPayloadsRandom(prev => prev.map(p => {
                const found = (data?.payloads || []).find(r => r.payload === p.payload);
                if (found) {
                    return { ...p, bypassed: found.bypassed, status_code: found.status_code };
                }
                return p;
            }));
        } catch (err) {
            setError(err.message || 'Failed to connect to backend');
        } finally {
            setLoadingAttackRandom(false);
        }
    };

    // Step 3: Test Attack on DVWA for Adaptive Payloads (update payloadsAdaptive in place)
    const handleTestAttackAdaptive = async () => {
        setLoadingAttackAdaptive(true);
        setError(null);
        try {
            const res = await Services.apiAttackDVWA(domain, payloadsAdaptive);
            const data = await res.json();
            if (!res.ok) {
                setError(data?.error || `Server error: ${res.status}`);
                return;
            }
            setPayloadsAdaptive(prev => prev.map(p => {
                const found = (data?.payloads || []).find(r => r.payload === p.payload);
                if (found) {
                    return { ...p, bypassed: found.bypassed, status_code: found.status_code };
                }
                return p;
            }));
        } catch (err) {
            setError(err.message || 'Failed to connect to backend');
        } finally {
            setLoadingAttackAdaptive(false);
        }
    };

    const handleClearPayloads = (type) => {
        if (type === 'random') {
            setPayloadsRandom([]);
        } else if (type === 'adaptive') {
            setPayloadsAdaptive([]);
        }
    }

    // Overlay for disabling UI when any loading
    const anyLoading = loadingDetect || loadingGenRandom || loadingGenAdaptive || loadingAttackRandom || loadingAttackAdaptive;

    return (
        <div className="relative space-y-8">
            {anyLoading && (
                <div className="absolute inset-0 z-40 bg-black/30 cursor-not-allowed" style={{ pointerEvents: 'all' }}></div>
            )}
            {/* Step 1: Detect WAF */}
            <div className="mb-8 p-8 rounded-2xl shadow-2xl bg-white/90 dark:bg-gray-900/80 backdrop-blur-md">
                <h2 className="text-xl font-bold mb-4 text-red-600 dark:text-red-400 tracking-tight">Bước 1: Nhập domain và phát hiện WAF</h2>
                <div className="flex flex-col md:flex-row gap-4 items-center mb-4">
                    <input
                        type="text"
                        className={`flex-1 px-5 py-3 rounded-xl border-2 text-lg font-medium shadow-sm focus:ring-2 focus:ring-red-400 transition-all duration-200 ${darkMode ? 'bg-gray-800 text-white border-gray-700 placeholder-gray-400' : 'bg-white text-gray-900 border-gray-300 placeholder-gray-400'}`}
                        placeholder="Target Domain (e.g., modsec.llmshield.click)"
                        onChange={e => setDomain(e.target.value)}
                        value={domain}
                        required
                        disabled={anyLoading}
                    />
                    <button
                        className="px-8 py-3 rounded-xl font-bold text-white bg-gradient-to-r from-red-500 to-pink-600 hover:from-red-600 hover:to-pink-700 disabled:from-gray-400 disabled:to-gray-500 shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed"
                        onClick={handleDetectWAFClick}
                        disabled={anyLoading || !domain || loadingDetect}
                        type="button"
                    >
                        {loadingDetect ? '🔄 Detecting...' : '🔍 Detect WAF'}
                    </button>
                </div>
                <textarea
                    className={`w-full h-16 border-2 rounded-xl p-3 text-base font-mono transition-colors duration-200 ${darkMode ? 'bg-gray-900 border-gray-700 text-cyan-400' : 'bg-gray-50 border-gray-300 text-gray-800'}`}
                    value={wafName || ''}
                    onChange={e => setWafName(e.target.value)}
                    placeholder="WAF name sẽ hiện ở đây..."
                />
            </div>

            {/* Step 2: Generate Payloads */}
            <div className="mb-8 p-8 rounded-2xl shadow-2xl bg-white/90 dark:bg-gray-900/80 backdrop-blur-md">
                <h2 className="text-xl font-bold mb-4 text-orange-600 dark:text-orange-400 tracking-tight">Bước 2: Sinh payloads</h2>
                <div className="flex flex-col md:flex-row gap-4 items-center mb-4 flex-wrap">
                    <select
                        className={`px-5 py-3 rounded-xl border-2 text-lg font-medium shadow-sm focus:ring-2 focus:ring-orange-400 transition-all duration-200 ${darkMode ? 'bg-gray-800 text-white border-gray-700' : 'bg-white text-gray-900 border-gray-300'}`}
                        value={attackType}
                        onChange={e => setAttackType(e.target.value)}
                        disabled={anyLoading}
                    >
                        <option value="xss_dom">XSS DOM-Based</option>
                        <option value="xss_reflected">XSS Reflected</option>
                        <option value="xss_stored">XSS Stored</option>
                        <option value="sql_injection">SQL Injection</option>
                        <option value="sql_injection_blind">Blind SQL Injection</option>
                    </select>
                    <input
                        type="number"
                        className={`w-28 px-5 py-3 rounded-xl border-2 text-center text-lg font-medium shadow-sm focus:ring-2 focus:ring-orange-400 transition-all duration-200 ${darkMode ? 'bg-gray-800 text-white border-gray-700' : 'bg-white text-gray-900 border-gray-300'}`}
                        placeholder="#"
                        min="1"
                        max="20"
                        value={numPayloads}
                        onChange={e => setNumPayloads(parseInt(e.target.value) || 5)}
                        title="Number of payloads (1-20)"
                        disabled={anyLoading}
                    />
                    <button
                        className="px-8 py-3 rounded-xl font-bold text-white bg-gradient-to-r from-orange-500 to-pink-600 hover:from-orange-600 hover:to-pink-700 disabled:from-gray-400 disabled:to-gray-500 shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed"
                        onClick={handleGenerateRandomPayloadsClick}
                        disabled={anyLoading || loadingGenRandom}
                        type="button"
                    >
                        {loadingGenRandom ? '🔄 Generating...' : '🚀 Generate Random Payloads'}
                    </button>
                    <button
                        className="px-8 py-3 rounded-xl font-bold text-white bg-gradient-to-r from-orange-600 to-pink-700 hover:from-orange-700 hover:to-pink-800 disabled:from-gray-400 disabled:to-gray-500 shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed"
                        onClick={handleGenerateAdaptivePayloadsClick}
                        disabled={anyLoading || !payloadsRandom || payloadsRandom.length === 0 || loadingGenAdaptive}
                        type="button"
                    >
                        {loadingGenAdaptive ? '🔄 Generating...' : '🤖 Generate Adaptive Payloads'}
                    </button>
                </div>
            </div>

            {/* Step 2.2 & 2.3: Two columns for random/adaptive */}
            <div className="mb-8 flex flex-col md:flex-row gap-8">
                {/* Random Payloads Column */}
                <div className="flex-1 p-6 rounded-2xl bg-white/90 dark:bg-gray-900/80 shadow flex flex-col gap-3">
                    <h2 className="font-bold text-lg mb-3 text-orange-700 dark:text-orange-300 tracking-tight">Random Payloads</h2>
                    <div className="flex flex-wrap gap-4 items-center mb-4">
                        <label className="px-4 py-2 rounded-lg font-semibold text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 cursor-pointer hover:bg-gray-300 dark:hover:bg-gray-600 transition-all duration-200">
                            <span className="text-base">📥</span> Import
                            <input type="file" accept="application/json" className="hidden" onChange={e => handleImportPayloadsGeneric(e, setPayloadsRandom)} disabled={anyLoading} />
                        </label>
                        <button
                            className="px-4 py-2 rounded-lg font-semibold text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600 transition-all duration-200"
                            onClick={() => handleExportPayloadsGeneric(payloadsRandom, 'payloads_random.json')}
                            disabled={!payloadsRandom.length || anyLoading}
                            type="button"
                        >
                            <span className="text-base">📤</span> Export
                        </button>
                    </div>
                    <div className="overflow-y-auto rounded-xl border border-gray-200 dark:border-gray-700" style={{maxHeight: 340}}>
                        <PayloadResultsTable wafName={wafName} payloads={payloadsRandom} darkMode={darkMode} onClear={() => handleClearPayloads("random")} />
                    </div>
                    <button
                        className="px-8 py-3 rounded-xl font-bold text-white bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 disabled:from-gray-400 disabled:to-gray-500 shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed"
                        onClick={handleTestAttackRandom}
                        disabled={anyLoading || !payloadsRandom.length || loadingAttackRandom}
                        type="button"
                    >
                        {loadingAttackRandom ? '🔄 Attacking...' : '🧪 Attack to DVWA'}
                    </button>
                    <button
                        className="mt-2 px-8 py-3 rounded-xl font-bold text-white bg-gradient-to-r from-blue-500 to-cyan-600 hover:from-blue-600 hover:to-cyan-700 disabled:from-gray-400 disabled:to-gray-500 shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed"
                        onClick={() => {setAttackResults(payloadsRandom); setActiveTab('Defend');}}
                        disabled={!payloadsRandom.length || anyLoading}
                        type="button"
                    >
                        🛡️ Defend
                    </button>
                </div>
                {/* Adaptive Payloads Column */}
                <div className="flex-1 p-6 rounded-2xl bg-white/90 dark:bg-gray-900/80 shadow flex flex-col gap-3">
                    <h2 className="font-bold text-lg mb-3 text-pink-700 dark:text-pink-300 tracking-tight">Adaptive Payloads</h2>
                    <div className="flex flex-wrap gap-4 items-center mb-4">
                        <label className="px-4 py-2 rounded-lg font-semibold text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 cursor-pointer hover:bg-gray-300 dark:hover:bg-gray-600 transition-all duration-200">
                            <span className="text-base">📥</span> Import
                            <input type="file" accept="application/json" className="hidden" onChange={e => handleImportPayloadsGeneric(e, setPayloadsAdaptive)} disabled={anyLoading} />
                        </label>
                        <button
                            className="px-4 py-2 rounded-lg font-semibold text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600 transition-all duration-200"
                            onClick={() => handleExportPayloadsGeneric(payloadsAdaptive, 'payloads_adaptive.json')}
                            disabled={!payloadsAdaptive.length || anyLoading}
                            type="button"
                        >
                            <span className="text-base">📤</span> Export
                        </button>
                    </div>
                    <div className="overflow-y-auto rounded-xl border border-gray-200 dark:border-gray-700" style={{maxHeight: 340}}>
                        <PayloadResultsTable wafName={wafName} payloads={payloadsAdaptive} darkMode={darkMode} onClear={() => handleClearPayloads("adaptive")}/>
                    </div>
                    <button
                        className="px-8 py-3 rounded-xl font-bold text-white bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 disabled:from-gray-400 disabled:to-gray-500 shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed"
                        onClick={handleTestAttackAdaptive}
                        disabled={anyLoading || !payloadsAdaptive.length || loadingAttackAdaptive}
                        type="button"
                    >
                        {loadingAttackAdaptive ? '🔄 Attacking...' : '🧪 Attack to DVWA'}
                    </button>
                    <button
                        className="mt-2 px-8 py-3 rounded-xl font-bold text-white bg-gradient-to-r from-blue-500 to-cyan-600 hover:from-blue-600 hover:to-cyan-700 disabled:from-gray-400 disabled:to-gray-500 shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed"
                        onClick={() => {setAttackResults(payloadsAdaptive); setActiveTab('Defend');}}
                        disabled={!payloadsAdaptive.length || anyLoading}
                        type="button"
                    >
                        🛡️ Defend
                    </button>
                </div>
            </div>

            {/* Error popup */}
            {error && (
                <div className="mt-2 p-3 rounded-xl bg-red-100 border-2 border-red-400 text-red-800 font-semibold shadow">
                    ⚠️ {error}
                </div>
            )}
        </div>
    );
}
export default AttackTab;