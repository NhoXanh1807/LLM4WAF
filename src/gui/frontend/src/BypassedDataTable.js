import React from 'react';

function BypassedDataTable({ wafInfo, payloads, instructions, darkMode }) {
    const data = Array.isArray(payloads) ? payloads : [];

    const getInstructions = idx => {
        if (Array.isArray(instructions) && instructions[idx]) {
            if (Array.isArray(instructions[idx].instruction)) {
                return instructions[idx].instruction.join(' | ');
            }
            return instructions[idx].instruction || JSON.stringify(instructions[idx]);
        }
        return '';
    };

    const getStatusBadge = (item) => {
        if (item.bypassed === true) {
            return <span className="px-4 py-1.5 bg-gradient-to-r from-red-500 to-pink-600 text-white rounded-full font-bold text-xs shadow-lg">⚠️ BYPASSED</span>;
        } else if (item.bypassed === false && item.status_code) {
            return <span className="px-4 py-1.5 bg-gradient-to-r from-green-500 to-emerald-600 text-white rounded-full font-bold text-xs shadow-lg">✅ BLOCKED</span>;
        }
        return <span className="px-4 py-1.5 bg-gray-400 text-white rounded-full text-xs">⏳ PENDING</span>;
    };

    return (
        <div className="overflow-x-auto">
            <div className="mb-6">
                <h3 className={`font-bold mb-3 text-lg ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>📋 WAF Information</h3>
                <textarea
                    className={`w-full h-28 border-2 rounded-lg p-4 text-sm font-mono transition-colors duration-200 ${
                        darkMode
                            ? 'bg-gray-900 border-gray-700 text-cyan-400'
                            : 'bg-gray-50 border-gray-300 text-gray-800'
                    }`}
                    value={wafInfo ? (typeof wafInfo === 'string' ? wafInfo : JSON.stringify(wafInfo, null, 2)) : ''}
                    readOnly
                />
            </div>
            <div className={`rounded-xl overflow-hidden border-2 ${darkMode ? 'border-gray-700' : 'border-gray-200'} shadow-lg`}>
                <table className="min-w-full table-fixed">
                    <thead>
                        <tr className={darkMode ? 'bg-gray-700' : 'bg-gradient-to-r from-gray-100 to-gray-200'}>
                            <th className={`w-12 px-4 py-3 font-bold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>#</th>
                            <th className={`w-32 px-4 py-3 font-bold text-left ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Attack Type</th>
                            <th className={`w-1/4 px-4 py-3 font-bold text-left ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Payload</th>
                            <th className={`px-4 py-3 font-bold text-left ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Instructions</th>
                            <th className={`w-20 px-4 py-3 font-bold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Status</th>
                            <th className={`w-40 px-4 py-3 font-bold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Result</th>
                        </tr>
                    </thead>
                    <tbody>
                        {data.map((item, idx) => (
                            <tr key={idx} className={`border-t transition-colors ${
                                item.bypassed
                                    ? (darkMode ? 'bg-red-900/20 border-red-800' : 'bg-red-50 border-red-200')
                                    : (darkMode ? 'bg-gray-800/50 border-gray-700' : 'bg-white border-gray-200')
                            } hover:${darkMode ? 'bg-gray-700' : 'bg-gray-50'}`}>
                                <td className={`px-4 py-3 text-center font-semibold ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>{idx + 1}</td>
                                <td className={`px-4 py-3 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                    <span className={`px-2 py-1 rounded text-xs font-semibold ${darkMode ? 'bg-purple-900/30 text-purple-400' : 'bg-purple-100 text-purple-700'}`}>
                                        {item.attack_type || 'N/A'}
                                    </span>
                                </td>
                                <td className={`px-4 py-3 font-mono text-xs break-all ${darkMode ? 'text-yellow-400' : 'text-gray-800'}`}>
                                    {item.payload || JSON.stringify(item)}
                                </td>
                                <td className={`px-4 py-3 text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                    {getInstructions(idx)}
                                </td>
                                <td className={`px-4 py-3 text-center font-mono font-bold ${darkMode ? 'text-cyan-400' : 'text-blue-600'}`}>
                                    {item.status_code || '-'}
                                </td>
                                <td className="px-4 py-3 text-center whitespace-nowrap">{getStatusBadge(item)}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

export default BypassedDataTable;
