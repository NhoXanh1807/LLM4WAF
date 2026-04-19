
import React, { useState } from 'react';
import {Services} from '../services';
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
    darkMode
}) => {
    // State cho import/export
    const [importedPayloads, setImportedPayloads] = useState([]);
    const [importedTestResults, setImportedTestResults] = useState([]);

    // Step 1: Detect WAF
    const handleDetectWAFClick = async () => {
        setIsSubmitting(true);
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
            setIsSubmitting(false);
        }
    };

    // Step 2: Generate Payloads
    const handleGeneratePayloadsClick = async () => {
        setIsSubmitting(true);
        setError(null);
        try {
            const res = await Services.apiGeneratePayload(wafName, attackType, numPayloads, []);
            const data = await res.json();
            if (!res.ok) {
                setError(data?.error || `Server error: ${res.status}`);
                setPayloads([]);
                return;
            }
            setPayloads(data?.payloads || []);
        } catch (err) {
            setError(err.message || 'Failed to connect to backend');
            setPayloads([]);
        } finally {
            setIsSubmitting(false);
        }
    };

    // Step 2: Import/Export Payloads
    const handleImportPayloads = (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (evt) => {
            try {
                const imported = JSON.parse(evt.target.result);
                setPayloads(imported);
            } catch {
                setError('Invalid payloads file');
            }
        };
        reader.readAsText(file);
    };
    const handleExportPayloads = () => {
        const blob = new Blob([JSON.stringify(payloads, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'payloads.json';
        a.click();
        URL.revokeObjectURL(url);
    };

    // Step 3: Test Attack on DVWA
    const handleTestAttackClick = async () => {
        setIsSubmitting(true);
        setError(null);
        try {
            const res = await Services.apiAttackDVWA(domain, payloads);
            const data = await res.json();
            if (!res.ok) {
                setError(data?.error || `Server error: ${res.status}`);
                return;
            }
            setPayloads(data?.payloads || []);
        } catch (err) {
            setError(err.message || 'Failed to connect to backend');
        } finally {
            setIsSubmitting(false);
        }
    };
    // Step 3: Import/Export Test Results
    const handleImportTestResults = (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (evt) => {
            try {
                const imported = JSON.parse(evt.target.result);
                setPayloads(imported);
            } catch {
                setError('Invalid test results file');
            }
        };
        reader.readAsText(file);
    };
    const handleExportTestResults = () => {
        const blob = new Blob([JSON.stringify(payloads, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'test_results.json';
        a.click();
        URL.revokeObjectURL(url);
    };

    const handleClearPayloads = () => {
        setPayloads([]);
    }

    return (
        <div className="space-y-10">
            {/* Step 1: Detect WAF */}
            <div className="mb-8 p-6 rounded-xl border-2 border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900/40 shadow">
                <h2 className="font-bold text-lg mb-3 text-red-600 dark:text-red-400">Bước 1: Nhập domain và phát hiện WAF</h2>
                <div className="flex flex-wrap gap-4 items-center mb-4">
                    <input
                        type="text"
                        className={`flex-1 px-4 py-3 rounded-lg font-medium transition-all duration-200 ${darkMode
                            ? 'bg-gray-700 text-white border-gray-600 placeholder-gray-400'
                            : 'bg-white text-gray-900 border-gray-300 placeholder-gray-500'
                            } border-2 focus:outline-none focus:ring-2 focus:ring-red-500`}
                        placeholder="Target Domain (e.g., modsec.llmshield.click)"
                        onChange={e => setDomain(e.target.value)}
                        value={domain}
                        required
                        disabled={isSubmitting}
                    />
                    <button
                        className="px-8 py-3 rounded-lg font-bold text-white bg-gradient-to-r from-red-500 to-pink-600 hover:from-red-600 hover:to-pink-700 disabled:from-gray-400 disabled:to-gray-500 shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed"
                        onClick={handleDetectWAFClick}
                        disabled={isSubmitting || !domain}
                        type="button"
                    >
                        {isSubmitting ? '🔄 Detecting...' : '🔍 Detect WAF'}
                    </button>
                </div>
                <div className="mb-2">
                    <label className="block font-semibold mb-1 text-gray-700 dark:text-gray-300">WAF Name</label>
                    <textarea
                        className={`w-full h-16 border-2 rounded-lg p-3 text-sm font-mono transition-colors duration-200 ${darkMode
                            ? 'bg-gray-900 border-gray-700 text-cyan-400'
                            : 'bg-gray-50 border-gray-300 text-gray-800'
                            }`}
                        value={wafName || ''}
                        onChange={e => setWafName(e.target.value)}
                        placeholder="WAF name sẽ hiện ở đây..."
                    />
                </div>
            </div>

            {/* Step 2: Generate Payloads */}
            <div className="mb-8 p-6 rounded-xl border-2 border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900/40 shadow opacity-100" style={{ opacity: wafName ? 1 : 0.5, pointerEvents: wafName ? 'auto' : 'none' }}>
                <h2 className="font-bold text-lg mb-3 text-orange-600 dark:text-orange-400">Bước 2: Sinh payloads ngẫu nhiên</h2>
                <div className="flex flex-wrap gap-4 items-center mb-4">
                    <select
                        className={`px-4 py-3 rounded-lg font-medium transition-all duration-200 ${darkMode
                            ? 'bg-gray-700 text-white border-gray-600 hover:bg-gray-600'
                            : 'bg-white text-gray-900 border-gray-300 hover:border-red-400'
                            } border-2 focus:outline-none focus:ring-2 focus:ring-red-500`}
                        value={attackType}
                        onChange={e => setAttackType(e.target.value)}
                        disabled={!wafName || isSubmitting}
                    >
                        <option value="xss_dom">XSS DOM-Based</option>
                        <option value="xss_reflected">XSS Reflected</option>
                        <option value="xss_stored">XSS Stored</option>
                        <option value="sql_injection">SQL Injection</option>
                        <option value="sql_injection_blind">Blind SQL Injection</option>
                    </select>
                    <input
                        type="number"
                        className={`w-28 px-4 py-3 rounded-lg font-medium text-center transition-all duration-200 ${darkMode
                            ? 'bg-gray-700 text-white border-gray-600'
                            : 'bg-white text-gray-900 border-gray-300'
                            } border-2 focus:outline-none focus:ring-2 focus:ring-red-500`}
                        placeholder="#"
                        min="1"
                        max="20"
                        value={numPayloads}
                        onChange={e => setNumPayloads(parseInt(e.target.value) || 5)}
                        title="Number of payloads (1-20)"
                        disabled={!wafName || isSubmitting}
                    />
                    <button
                        className="px-8 py-3 rounded-lg font-bold text-white bg-gradient-to-r from-orange-500 to-pink-600 hover:from-orange-600 hover:to-pink-700 disabled:from-gray-400 disabled:to-gray-500 shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed"
                        onClick={handleGeneratePayloadsClick}
                        disabled={!wafName || isSubmitting}
                        type="button"
                    >
                        {isSubmitting ? '🔄 Generating...' : '🚀 Generate Random Payloads'}
                    </button>
                    {/* Import/Export payloads */}
                    <label className="px-4 py-2 rounded-lg font-semibold text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 cursor-pointer hover:bg-gray-300 dark:hover:bg-gray-600 transition-all duration-200">
                        📥 Import
                        <input type="file" accept="application/json" className="hidden" onChange={handleImportPayloads} disabled={isSubmitting} />
                    </label>
                    <button
                        className="px-4 py-2 rounded-lg font-semibold text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600 transition-all duration-200"
                        onClick={handleExportPayloads}
                        disabled={!payloads.length}
                        type="button"
                    >
                        📤 Export
                    </button>
                </div>
            </div>


            {/* Step 3: Test Attack on DVWA */}
            <div className="mb-8 p-6 rounded-xl border-2 border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900/40 shadow opacity-100" style={{ opacity: payloads.length > 0 ? 1 : 0.5, pointerEvents: payloads.length > 0 ? 'auto' : 'none' }}>
                <h2 className="font-bold text-lg mb-3 text-green-600 dark:text-green-400">Bước 3: Test Attack WAF on DVWA</h2>
                <div className="flex flex-wrap gap-4 items-center mb-4">
                    <button
                        className="px-8 py-3 rounded-lg font-bold text-white bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 disabled:from-gray-400 disabled:to-gray-500 shadow-lg hover:shadow-xl transition-all duration-200 disabled:cursor-not-allowed"
                        onClick={handleTestAttackClick}
                        disabled={isSubmitting || !payloads.length}
                        type="button"
                    >
                        {isSubmitting ? '🔄 Testing...' : '🧪 Test Attack on DVWA'}
                    </button>
                    {/* Import/Export test results */}
                    <label className="px-4 py-2 rounded-lg font-semibold text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 cursor-pointer hover:bg-gray-300 dark:hover:bg-gray-600 transition-all duration-200">
                        📥 Import
                        <input type="file" accept="application/json" className="hidden" onChange={handleImportTestResults} disabled={isSubmitting} />
                    </label>
                    <button
                        className="px-4 py-2 rounded-lg font-semibold text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600 transition-all duration-200"
                        onClick={handleExportTestResults}
                        disabled={!payloads.length}
                        type="button"
                    >
                        📤 Export
                    </button>
                </div>
            </div>

            {/* Error hiển thị chung */}
            {error && (
                <div className="mt-4 p-4 rounded-lg bg-red-100 border border-red-400 text-red-800 font-semibold">
                    ⚠️ {error}
                </div>
            )}

            {/* Hiển thị bảng payloads nếu có */}
            {payloads.length > 0 && (
                <PayloadResultsTable onClear={handleClearPayloads} wafName={wafName} payloads={payloads} darkMode={darkMode} />
            )}

        </div>
    );
}
export default AttackTab;