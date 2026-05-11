
import React, { useState } from 'react';
import { Services } from '../services';
import PayloadResultsTable from './PayloadResultsTable';

const EMPTY_PROGRESS = { current: 0, total: 0 };

const buildPayloadIdentity = item => `${item?.payload || ''}::${item?.technique || ''}::${item?.attack_type || ''}`;

const AttackTab = ({
    domain,
    setDomain,
    attackType,
    setAttackType,
    numPayloads,
    setNumPayloads,
    error,
    setError,
    wafName,
    setWafName,
    darkMode,
    payloadsRandom,
    setPayloadsRandom,
    payloadsAdaptive,
    setPayloadsAdaptive,
    setAttackResults,
    setActiveTab,
}) => {
    // Per-button loading states
    const [loadingDetect, setLoadingDetect] = useState(false);
    const [loadingGenRandom, setLoadingGenRandom] = useState(false);
    const [loadingGenAdaptive, setLoadingGenAdaptive] = useState(false);
    const [loadingAttackRandom, setLoadingAttackRandom] = useState(false);
    const [loadingAttackAdaptive, setLoadingAttackAdaptive] = useState(false);
    // State cho auto attack
    const [autoUseAdaptive, setAutoUseAdaptive] = useState(false);
    const [autoNumAdaptive, setAutoNumAdaptive] = useState(5);
    const [loadingAutoAttack, setLoadingAutoAttack] = useState(false);
    const [randomGenerateProgress, setRandomGenerateProgress] = useState(EMPTY_PROGRESS);
    const [adaptiveGenerateProgress, setAdaptiveGenerateProgress] = useState(EMPTY_PROGRESS);
    const [randomTestProgress, setRandomTestProgress] = useState(EMPTY_PROGRESS);
    const [adaptiveTestProgress, setAdaptiveTestProgress] = useState(EMPTY_PROGRESS);

    const formatProgressText = (label, progress) => {
        if (!progress.total) {
            return null;
        }

        return `${label}: ${progress.current}/${progress.total}`;
    };

    const getQualifiedDefendPayloads = () => {
        const combinedPayloads = [...payloadsRandom, ...payloadsAdaptive];
        const seen = new Set();

        return combinedPayloads.filter(item => {
            const hasFullAttackResult = item?.is_bypassed != null && item?.is_harmful != null;
            if (!hasFullAttackResult) {
                return false;
            }

            const identity = buildPayloadIdentity(item);
            if (seen.has(identity)) {
                return false;
            }

            seen.add(identity);
            return true;
        }).filter(item => item.is_bypassed === true && item.is_harmful === true);
    };

    const getAdaptiveHistoryPayloads = (payloads = []) => (
        payloads.filter(item => item?.is_bypassed != null && item?.is_harmful != null)
    );

    const requestSinglePayload = async (currentWafName, currentAttackType, payloadsHistory = [], errorLabel = 'Generate payload') => {
        const res = await Services.apiGeneratePayload(currentWafName, currentAttackType, 1, payloadsHistory);
        const data = await res.json();
        if (!res.ok) {
            throw new Error(data?.error || `${errorLabel} error: ${res.status}`);
        }

        return (data?.payloads || [])[0] || null;
    };

    const mergeAttackResult = (payload, result) => (
        result
            ? {
                ...payload,
                is_bypassed: result.is_bypassed,
                status_code: result.status_code,
                is_harmful: result.is_harmful,
            }
            : payload
    );

    const testPayloadsSequentially = async (currentDomain, payloads, setPayloadsFn, setProgressFn) => {
        const nextPayloads = [...payloads];
        setPayloadsFn(nextPayloads);
        setProgressFn({ current: 0, total: nextPayloads.length });

        for (let index = 0; index < nextPayloads.length; index += 1) {
            const currentPayload = nextPayloads[index];
            const res = await Services.apiTestAttack(currentDomain, [currentPayload]);
            const data = await res.json();
            if (!res.ok) {
                throw new Error(data?.error || `Attack DVWA error: ${res.status}`);
            }

            const found = (data?.payloads || []).find(result => result.payload === currentPayload.payload);
            nextPayloads[index] = mergeAttackResult(currentPayload, found);
            setPayloadsFn([...nextPayloads]);
            setProgressFn({ current: index + 1, total: nextPayloads.length });
        }

        return nextPayloads;
    };

    const generateRandomPayloadsSequentially = async (currentWafName, currentAttackType, totalPayloads) => {
        const generatedPayloads = [];
        setPayloadsRandom([]);
        setRandomGenerateProgress({ current: 0, total: totalPayloads });

        for (let index = 0; index < totalPayloads; index += 1) {
            const nextPayload = await requestSinglePayload(
                currentWafName,
                currentAttackType,
                [],
                'Generate random payloads',
            );

            if (nextPayload) {
                generatedPayloads.push(nextPayload);
                setPayloadsRandom([...generatedPayloads]);
            }
            setRandomGenerateProgress({ current: index + 1, total: totalPayloads });
        }

        return generatedPayloads;
    };

    const generateAdaptivePayloadsSequentially = async (currentWafName, currentAttackType, totalPayloads, payloadHistory) => {
        const generatedPayloads = [];
        const qualifiedHistory = getAdaptiveHistoryPayloads(payloadHistory);

        if (!qualifiedHistory.length) {
            throw new Error('Adaptive attack requires payloads that already have both is_bypassed and is_harmful results');
        }

        setPayloadsAdaptive([]);
        setAdaptiveGenerateProgress({ current: 0, total: totalPayloads });

        for (let index = 0; index < totalPayloads; index += 1) {
            const nextPayload = await requestSinglePayload(
                currentWafName,
                currentAttackType,
                [...qualifiedHistory, ...generatedPayloads],
                'Generate adaptive payloads',
            );

            if (nextPayload) {
                generatedPayloads.push(nextPayload);
                setPayloadsAdaptive([...generatedPayloads]);
            }
            setAdaptiveGenerateProgress({ current: index + 1, total: totalPayloads });
        }

        return generatedPayloads;
    };

    // Hàm auto attack
    const handleAutoAttack = async () => {
        setLoadingAutoAttack(true);
        setError(null);
        try {
            setRandomGenerateProgress(EMPTY_PROGRESS);
            setAdaptiveGenerateProgress(EMPTY_PROGRESS);
            setRandomTestProgress(EMPTY_PROGRESS);
            setAdaptiveTestProgress(EMPTY_PROGRESS);
            // Step 1 - Detect WAF
            setWafName('');
            setPayloadsRandom([]);
            setPayloadsAdaptive([]);
            setNumPayloads(numPayloads);
            var wafNameVal = '';
            setLoadingDetect(true);
            try {
                let res = await Services.apiDetectWAF(domain);
                let data = await res.json();
                if (!res.ok) throw new Error(data?.error || `Detect WAF error: ${res.status}`);
                wafNameVal = data?.waf_name || '';
                setWafName(wafNameVal);
            }
            finally {
                setLoadingDetect(false);
            }
            if (!wafNameVal) {
                setError('No WAF detected, cannot proceed with attack');
                return;
            }

            // Step 2 - Generate Random Payloads
            var randomPayloads = [];
            setLoadingGenRandom(true);
            try {
                randomPayloads = await generateRandomPayloadsSequentially(wafNameVal, attackType, numPayloads);
            }
            finally {
                setLoadingGenRandom(false);
            }
            if (randomPayloads.length === 0) {
                setError('No random payloads generated, cannot proceed with attack');
                return;
            }

            // Step 2.1: Attack DVWA with random payloads to get initial feedback
            setLoadingAttackRandom(true);
            let is_attack_successful = false;
            try {
                randomPayloads = await testPayloadsSequentially(domain, randomPayloads, setPayloadsRandom, setRandomTestProgress);
                is_attack_successful = !randomPayloads.some(p => p.is_bypassed == null && p.status_code == null && p.is_harmful == null); // Nếu tất cả payload đều có kết quả (bypassed hoặc status_code hoặc is_harmful) thì coi như attack thành công
            }
            finally {
                setLoadingAttackRandom(false);
            }
            if (!is_attack_successful) {
                throw new Error('Initial attack with random payloads failed, cannot proceed with adaptive attack');
            }

            var autoAttackResults = randomPayloads;
            // Step 3 - Nếu dùng adaptive thì generate adaptive payloads
            if (autoUseAdaptive) {
                setLoadingGenAdaptive(true);
                let adaptivePayloads = [];
                try {
                    adaptivePayloads = await generateAdaptivePayloadsSequentially(wafNameVal, attackType, autoNumAdaptive, randomPayloads);
                }
                finally {
                    setLoadingGenAdaptive(false);
                }

                // Step 3.1: Attack DVWA with adaptive payloads
                let is_attack_adaptive_successful = false;
                setLoadingAttackAdaptive(true);
                try {
                    adaptivePayloads = await testPayloadsSequentially(domain, adaptivePayloads, setPayloadsAdaptive, setAdaptiveTestProgress);
                    is_attack_adaptive_successful = !adaptivePayloads.some(p => p.is_bypassed == null && p.status_code == null && p.is_harmful == null); // Nếu tất cả payload đều có kết quả (bypassed hoặc status_code hoặc is_harmful) thì coi như attack thành công
                }
                finally {
                    setLoadingAttackAdaptive(false);
                }
                if (!is_attack_adaptive_successful) {
                    throw new Error('Adaptive attack failed, cannot complete the full attack pipeline');
                }
                autoAttackResults = [...randomPayloads, ...adaptivePayloads];
            }
            setAttackResults(autoAttackResults);
        } catch (err) {
            setError(err.message || 'Auto attack failed');
        } finally {
            setLoadingAutoAttack(false);
        }
    };

    // Step 1 - Detect WAF
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


    // Step 2 - Generate Random Payloads
    const handleGenerateRandomPayloadsClick = async () => {
        setLoadingGenRandom(true);
        setError(null);
        try {
            setRandomTestProgress(EMPTY_PROGRESS);
            await generateRandomPayloadsSequentially(wafName, attackType, numPayloads);
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
            setAdaptiveTestProgress(EMPTY_PROGRESS);
            await generateAdaptivePayloadsSequentially(wafName, attackType, numPayloads, payloadsRandom);
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

    // Step 3 - Test Attack on DVWA for Random Payloads (update payloadsRandom in place)
    const handleTestAttackRandom = async () => {
        setLoadingAttackRandom(true);
        setError(null);
        try {
            await testPayloadsSequentially(domain, payloadsRandom, setPayloadsRandom, setRandomTestProgress);
        } catch (err) {
            setError(err.message || 'Failed to connect to backend');
        } finally {
            setLoadingAttackRandom(false);
        }
    };

    // Step 3 - Test Attack on DVWA for Adaptive Payloads (update payloadsAdaptive in place)
    const handleTestAttackAdaptive = async () => {
        setLoadingAttackAdaptive(true);
        setError(null);
        try {
            await testPayloadsSequentially(domain, payloadsAdaptive, setPayloadsAdaptive, setAdaptiveTestProgress);
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

    const handleOpenDefendTab = () => {
        const defendPayloads = getQualifiedDefendPayloads();

        if (defendPayloads.length === 0) {
            setError('No payloads with both is_bypassed and is_harmful results are available for Defend');
            return;
        }

        setError(null);
        setAttackResults(defendPayloads);
        setActiveTab('Defend');
    };

    // Overlay for disabling UI when any loading
    const anyLoading = loadingDetect || loadingGenRandom || loadingGenAdaptive || loadingAttackRandom || loadingAttackAdaptive;
    const defendPayloads = getQualifiedDefendPayloads();

    return (
        <div className="relative gap-6 flex flex-col">
            {anyLoading && (
                <div className="absolute inset-0 z-40 bg-black/30 cursor-not-allowed" style={{ pointerEvents: 'all' }}></div>
            )}

            {/* Auto Attack All Steps Form */}
            <div className="p-4 rounded-2xl shadow-2xl bg-white/90 dark:bg-gray-900/80 backdrop-blur-md">
                <h2 className="text-3xl font-bold mb-4 text-red-500 tracking-tight">
                    Auto Attack All Steps
                </h2>
                <div className="flex flex-col gap-6">
                    <div className="flex flex-row gap-4 items-center">
                        <span className="text-lg font-medium dark:text-white">Domain</span>
                        <input
                            type="text"
                            className={`w-1/4 flex px-5 py-3 rounded-xl border-2 text-lg font-medium shadow-sm focus:ring-2 focus:ring-green-400 transition-all duration-200 ${darkMode ? 'bg-gray-800 text-white border-gray-700 placeholder-gray-400' : 'bg-white text-gray-900 border-gray-300 placeholder-gray-400'}`}
                            placeholder="Target Domain (e.g., modsec.llmshield.click)"
                            value={domain}
                            onChange={e => setDomain(e.target.value)}
                            required
                            disabled={loadingAutoAttack || anyLoading}
                        />
                        <span className="text-lg font-medium dark:text-white">AttackType</span>
                        <select
                            className={`px-5 py-3 rounded-xl border-2 text-lg font-medium shadow-sm focus:ring-2 focus:ring-green-400 transition-all duration-200 ${darkMode ? 'bg-gray-800 text-white border-gray-700' : 'bg-white text-gray-900 border-gray-300'}`}
                            value={attackType}
                            onChange={e => setAttackType(e.target.value)}
                            disabled={loadingAutoAttack || anyLoading}
                        >
                            <option value="xss_dom">XSS DOM-Based</option>
                            <option value="xss_reflected">XSS Reflected</option>
                            <option value="xss_stored">XSS Stored</option>
                            <option value="sql_injection">SQL Injection</option>
                            <option value="sql_injection_blind">Blind SQL Injection</option>
                        </select>
                        <span className="text-lg font-medium dark:text-white">NumPayloads</span>
                        <input
                            type="number"
                            className={`w-28 px-5 py-3 rounded-xl border-2 text-center text-lg font-medium shadow-sm focus:ring-2 focus:ring-green-400 transition-all duration-200 ${darkMode ? 'bg-gray-800 text-white border-gray-700' : 'bg-white text-gray-900 border-gray-300'}`}
                            placeholder="#"
                            min="1"
                            max="20"
                            value={numPayloads}
                            onChange={e => setNumPayloads(parseInt(e.target.value) || 5)}
                            title="Number of payloads (1-20)"
                            disabled={loadingAutoAttack || anyLoading}
                        />
                    </div>
                    <div className="flex flex-col gap-4 items-start">
                        <label className="flex items-center gap-2 cursor-pointer">
                            <input
                            className='h-6 w-6'
                                type="checkbox"
                                checked={autoUseAdaptive}
                                onChange={e => setAutoUseAdaptive(e.target.checked)}
                                disabled={loadingAutoAttack || anyLoading}
                            />
                            <span className="text-xl font-bold text-purple-700 dark:text-purple-400">Enable Adaptive Attack</span>
                        </label>
                        {autoUseAdaptive && (<div className='flex flex-row items-center gap-3'>
                            <span className="text-lg font-medium dark:text-white">Number of Adaptive Payloads : </span>
                            <input
                                type="number"
                                className={`w-32 px-5 py-3 rounded-xl border-2 text-center text-lg font-medium shadow-sm focus:ring-2 focus:ring-pink-400 transition-all duration-200 ${darkMode ? 'bg-gray-800 text-white border-gray-700' : 'bg-white text-gray-900 border-gray-300'}`}
                                placeholder="Số lượng adaptive payloads"
                                min="1"
                                max="20"
                                value={autoNumAdaptive}
                                onChange={e => setAutoNumAdaptive(parseInt(e.target.value) || 5)}
                                title="Số lượng adaptive payloads (1-20)"
                                disabled={loadingAutoAttack || anyLoading}
                            />
                        </div>
                        )}
                    </div>
                    <button
                        className={`px-8 py-3 rounded-xl font-bold text-white shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed
                            ${loadingAutoAttack
                                ? 'bg-gradient-to-r from-yellow-400 to-yellow-600'
                                : 'bg-gradient-to-r from-red-500 to-pink-600 hover:from-red-600 hover:to-pink-700 disabled:from-gray-400 disabled:to-gray-500'}
                        `}
                        onClick={(e) => { e.preventDefault(); handleAutoAttack() }}
                        disabled={loadingAutoAttack || anyLoading}
                    >
                        {loadingAutoAttack ? '🔄 Auto attacking all steps...' : '🚀 Auto Attack All Steps'}
                    </button>
                </div>
            </div>


            {/* Step 1 - Detect WAF */}
            <div className="p-4 rounded-2xl shadow-2xl bg-white/90 dark:bg-gray-900/80 backdrop-blur-md">
                <h2 className="text-xl font-bold mb-4 text-red-600 dark:text-red-400 tracking-tight">
                    Step 1 - Detect WAF
                </h2>
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
                        className={`px-8 py-3 rounded-xl font-bold text-white shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed
                            ${loadingDetect
                                ? 'bg-gradient-to-r from-yellow-400 to-yellow-600'
                                : 'bg-gradient-to-r from-red-500 to-pink-600 hover:from-red-600 hover:to-pink-700 disabled:from-gray-400 disabled:to-gray-500'}
                        `}
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

            {/* Step 2 - Generate Payloads */}
            <div className="p-4 rounded-2xl shadow-2xl bg-white/90 dark:bg-gray-900/80 backdrop-blur-md">
                <h2 className="text-xl font-bold mb-4 text-orange-600 dark:text-orange-400 tracking-tight">
                    Step 2 - Generate Payloads
                </h2>
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
                        className={`px-8 py-3 rounded-xl font-bold text-white shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed
                            ${loadingGenRandom
                                ? 'bg-gradient-to-r from-yellow-400 to-yellow-600'
                                : 'bg-gradient-to-r from-orange-500 to-pink-600 hover:from-orange-600 hover:to-pink-700 disabled:from-gray-400 disabled:to-gray-500'}
                        `}
                        onClick={handleGenerateRandomPayloadsClick}
                        disabled={anyLoading || loadingGenRandom}
                        type="button"
                    >
                        {loadingGenRandom ? '🔄 Generating random...' : '🚀 Generate Random Payloads'}
                    </button>
                    <button
                        className={`px-8 py-3 rounded-xl font-bold text-white shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed
                            ${loadingGenAdaptive
                                ? 'bg-gradient-to-r from-yellow-400 to-yellow-600'
                                : 'bg-gradient-to-r from-orange-600 to-pink-700 hover:from-orange-700 hover:to-pink-800 disabled:from-gray-400 disabled:to-gray-500'}
                        `}
                        onClick={handleGenerateAdaptivePayloadsClick}
                        disabled={anyLoading || getAdaptiveHistoryPayloads(payloadsRandom).length === 0 || loadingGenAdaptive}
                        type="button"
                    >
                        {loadingGenAdaptive ? '🔄 Generating adaptive...' : '🤖 Generate Adaptive Payloads'}
                    </button>
                </div>
                {payloadsRandom.length > 0 && getAdaptiveHistoryPayloads(payloadsRandom).length === 0 && (
                    <div className={`rounded-xl border border-dashed px-4 py-3 text-sm ${darkMode ? 'border-pink-900 text-pink-300' : 'border-pink-300 text-pink-700'}`}>
                        Adaptive attack is available only after random payloads have both bypass and harmfulness results.
                    </div>
                )}
            </div>

            {/* Step 2.2 & 2.3: Two columns for random/adaptive */}
            <div className="flex flex-col md:flex-row gap-8">
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
                    {(formatProgressText('Generated', randomGenerateProgress) || formatProgressText('Tested', randomTestProgress)) && (
                        <div className={`rounded-xl px-4 py-2 text-sm font-semibold ${darkMode ? 'bg-gray-800 text-cyan-300' : 'bg-cyan-50 text-cyan-800'}`}>
                            {[formatProgressText('Generated', randomGenerateProgress), formatProgressText('Tested', randomTestProgress)].filter(Boolean).join(' | ')}
                        </div>
                    )}
                    <PayloadResultsTable wafName={wafName} payloads={payloadsRandom} darkMode={darkMode} onClear={() => handleClearPayloads("random")} />
                    <button
                        className={`px-8 py-3 rounded-xl font-bold text-white shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed
                            ${loadingAttackRandom
                                ? 'bg-gradient-to-r from-yellow-400 to-yellow-600'
                                : 'bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 disabled:from-gray-400 disabled:to-gray-500'}
                        `}
                        onClick={handleTestAttackRandom}
                        disabled={anyLoading || !payloadsRandom.length || loadingAttackRandom}
                        type="button"
                    >
                        {loadingAttackRandom ? '🔄 Attacking...' : '🧪 Step 3 - Attack to DVWA'}
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
                    {(formatProgressText('Generated', adaptiveGenerateProgress) || formatProgressText('Tested', adaptiveTestProgress)) && (
                        <div className={`rounded-xl px-4 py-2 text-sm font-semibold ${darkMode ? 'bg-gray-800 text-pink-300' : 'bg-pink-50 text-pink-800'}`}>
                            {[formatProgressText('Generated', adaptiveGenerateProgress), formatProgressText('Tested', adaptiveTestProgress)].filter(Boolean).join(' | ')}
                        </div>
                    )}
                    <PayloadResultsTable wafName={wafName} payloads={payloadsAdaptive} darkMode={darkMode} onClear={() => handleClearPayloads("adaptive")} />
                    <button
                        className={`px-8 py-3 rounded-xl font-bold text-white shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed
                            ${loadingAttackAdaptive
                                ? 'bg-gradient-to-r from-yellow-400 to-yellow-600'
                                : 'bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 disabled:from-gray-400 disabled:to-gray-500'}
                        `}
                        onClick={handleTestAttackAdaptive}
                        disabled={anyLoading || !payloadsAdaptive.length || loadingAttackAdaptive}
                        type="button"
                    >
                        {loadingAttackAdaptive ? '🔄 Attacking...' : '🧪 Step 3 - Attack to DVWA'}
                    </button>
                </div>
            </div>

            <div className="p-4 rounded-2xl shadow-2xl bg-white/90 dark:bg-gray-900/80 backdrop-blur-md">
                <button
                    className="w-full px-8 py-4 rounded-xl font-bold text-white bg-gradient-to-r from-blue-500 to-cyan-600 hover:from-blue-600 hover:to-cyan-700 disabled:from-gray-400 disabled:to-gray-500 shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed"
                    onClick={handleOpenDefendTab}
                    disabled={anyLoading || defendPayloads.length === 0}
                    type="button"
                >
                    🛡️ Step 4 - Defend
                </button>
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