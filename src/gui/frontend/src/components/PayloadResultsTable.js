import React from 'react';

function PayloadResultsTable({ wafName, payloads, darkMode, onClear, maxHeight = 400 }) {
    const data = Array.isArray(payloads) ? payloads : [];

    // Statistics
    const total = data.length;
    const bypassed = data.filter(item => item.status_code != null && item.bypassed === true).length;
    const blocked = data.filter(item => item.status_code != null && item.bypassed === false).length;
    const notTested = data.filter(item => item.status_code == null).length;

    const getStatusBadge = (item) => {
        if (item.bypassed === true) {
            return <span className="px-4 py-1.5 bg-gradient-to-r from-red-500 to-pink-600 text-white rounded-full font-bold text-xs shadow-lg">⚠️ BYPASSED</span>;
        } else if (item.bypassed === false && item.status_code != null) {
            return <span className="px-4 py-1.5 bg-gradient-to-r from-green-500 to-emerald-600 text-white rounded-full font-bold text-xs shadow-lg">✅ BLOCKED</span>;
        }
        // If bypassed is null/undefined, treat as not tested
        return <span className="px-4 py-1.5 bg-gray-400 text-white rounded-full text-xs">--</span>;
    };

    return (
        <div className="overflow-x-auto">
            <div className="mb-6 flex items-center gap-4 flex-wrap">
                {onClear && (
                    <button
                        className="px-4 py-2 rounded-lg font-bold text-white bg-gradient-to-r from-red-500 to-pink-600 hover:from-red-600 hover:to-pink-700 shadow-lg hover:shadow-xl transition-all duration-200"
                        onClick={onClear}
                        type="button"
                    >
                        🧹 Clear
                    </button>
                )}
                <span className="ml-2 text-sm font-semibold text-gray-700 dark:text-gray-200">Nums of Payloads: {total}</span>
                <span className="text-xs font-semibold px-2 py-1 rounded bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300">Bypassed: {bypassed}</span>
                <span className="text-xs font-semibold px-2 py-1 rounded bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300">Blocked: {blocked}</span>
                <span className="text-xs font-semibold px-2 py-1 rounded bg-gray-100 text-gray-700 dark:bg-gray-800/60 dark:text-gray-300">Not tested: {notTested}</span>
            </div>
            <div
                className={`rounded-xl overflow-hidden border-2 ${darkMode ? 'border-gray-700' : 'border-gray-200'} shadow-lg`}
                style={{ maxHeight: maxHeight, overflowY: 'auto' }}
            >
                <table className="min-w-full table-fixed">
                    <thead>
                        <tr className={darkMode ? 'bg-gray-700' : 'bg-gradient-to-r from-gray-100 to-gray-200'}>
                            <th className={`w-12 px-2 py-3 font-bold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>#</th>
                            <th className={`w-12 px-2 py-3 font-bold text-left ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Type</th>
                            <th className={`w-full px-2 py-3 font-bold text-left ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Payload</th>
                            <th className={`w-20 px-2 py-3 font-bold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Status</th>
                            <th className={`w-40 px-2 py-3 font-bold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Result</th>
                        </tr>
                    </thead>
                    <tbody>
                        {data.map((item, idx) => (
                            <tr key={idx} className={`border-t transition-colors ${item.bypassed
                                    ? (darkMode ? 'bg-red-900/20 border-red-800' : 'bg-red-50 border-red-200')
                                    : (darkMode ? 'bg-gray-800/50 border-gray-700' : 'bg-white border-gray-200')
                                } hover:${darkMode ? 'bg-gray-700' : 'bg-gray-50'}`}>
                                <td className={`px-2 py-3 text-center font-semibold ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>{idx + 1}</td>
                                <td className={`px-2 py-3 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                    <span className={`px-2 py-1 rounded text-xs font-semibold ${darkMode ? 'bg-purple-900/30 text-purple-400' : 'bg-purple-100 text-purple-700'}`}>
                                        {item.attack_type || 'N/A'}
                                    </span>
                                </td>
                                <td className={`px-2 py-3 font-mono text-xs break-all ${darkMode ? 'text-yellow-400' : 'text-gray-800'}`}>
                                    {item.payload || JSON.stringify(item)}
                                </td>
                                <td className={`px-2 py-3 text-center font-mono font-bold ${darkMode ? 'text-cyan-400' : 'text-blue-600'}`}>
                                    {item.status_code == null ? '--' : item.status_code}
                                </td>
                                <td className="px-2 py-3 text-center whitespace-nowrap">{getStatusBadge(item)}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

export default PayloadResultsTable;
