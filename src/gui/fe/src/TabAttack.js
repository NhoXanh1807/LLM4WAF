import React, { useState } from 'react';

function TabAttack() {
    const [attackType, setAttackType] = useState('XSS');
    const [domain, setDomain] = useState('');
    const [log, setLog] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [resultDomainInfo, setResultDomainInfo] = useState(false);
    const [resultPayloads, setresultPayloads] = useState(false);
    const [resultInstructions, setResultInstructions] = useState(false);

    const handleSubmit = (e) => {
        e.preventDefault();
        setLog(`Đang kiểm tra domain: ${domain} với kiểu tấn công: ${attackType}...\nHoàn tất!`);
        setSubmitted(true);
    };

    const handleDownload = (filename) => {
        // Dummy download logic
        const data = `Nội dung file ${filename}`;
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    };

    return (
        <div className="space-y-6">
            <form className="flex items-center space-x-4" onSubmit={handleSubmit}>
                <select
                    className="border rounded px-3 py-2"
                    value={attackType}
                    onChange={e => setAttackType(e.target.value)}
                >
                    <option value="XSS">XSS</option>
                    <option value="File Upload">File Upload</option>
                </select>
                <input
                    type="text"
                    className="border rounded px-3 py-2 flex-1"
                    placeholder="Domain name..."
                    value={domain}
                    onChange={e => setDomain(e.target.value)}
                />
                <button
                    type="submit"
                    className="bg-red-500 text-white px-4 py-2 rounded font-bold hover:bg-red-600"
                >
                    Submit
                </button>
            </form>
            <textarea
                className="w-full h-32 border rounded p-2 text-sm bg-gray-50"
                value={log}
                readOnly
                placeholder="Log sẽ hiển thị ở đây..."
            />
            <div className="flex space-x-4">
                <button
                    className="px-4 py-2 rounded bg-green-500 text-white font-semibold disabled:bg-gray-300"
                    disabled={!submitted}
                    onClick={() => handleDownload('DomainInfo.json')}
                >
                    DomainInfo.json
                </button>
                <button
                    className="px-4 py-2 rounded bg-red-500 text-white font-semibold disabled:bg-gray-300"
                    disabled={!submitted}
                    onClick={() => handleDownload('Payloads.json')}
                >
                    Payloads.json
                </button>
                <button
                    className="px-4 py-2 rounded bg-blue-500 text-white font-semibold disabled:bg-gray-300"
                    disabled={!submitted}
                    onClick={() => handleDownload('Instructions.json')}
                >
                    Instructions.json
                </button>
            </div>
        </div>
    );
}

export default TabAttack;
