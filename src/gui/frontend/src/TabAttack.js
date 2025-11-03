import React, { useState } from 'react';
import { Services } from './services';

function TabAttack() {
    const [attackType, setAttackType] = useState('XSS');
    const [domain, setDomain] = useState('');
    const [logData, setLogData] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [result, setResult] = useState(null);

    const log = (message) => setLogData((prev) => prev + '\n' + message);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setIsSubmitting(true);
        try {
            log(`Kiểm tra thông tin tên miền: ${domain}`);

            const res = await Services.detectWAF(domain);
            const data = res.ok ? await res.json() : null;
            console.log(data);

            log(`Hoàn tất tên miền: ${domain}`);
            setResult({
                domain: data.output,
                payloads: { payloads: ['payload1', 'payload2'] },
                instructions: { instructions: ['step1', 'step2'] }
            })
        }
        finally {
            setIsSubmitting(false);
        }
    };

    const handleDownload = (filename) => {
        // Dummy download logic
        const data = result[filename];
        const blob = new Blob([data]);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename + ".json";
        a.click();
        a.remove();
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
                    disabled={isSubmitting || !domain}
                    className="bg-red-500 text-white px-4 py-2 rounded font-bold hover:bg-red-600 disabled:bg-gray-300"
                >
                    Submit
                </button>
            </form>
            <textarea
                className="w-full h-32 border rounded p-2 text-sm bg-gray-50"
                value={logData}
                readOnly
                placeholder="Log sẽ hiển thị ở đây..."
            />
            <div className="flex space-x-4">
                <button
                    className="px-4 py-2 rounded bg-green-500 text-white font-semibold disabled:bg-gray-300"
                    disabled={!result?.domain}
                    onClick={() => handleDownload('domain')}
                >
                    Domain Info
                </button>
                <button
                    className="px-4 py-2 rounded bg-red-500 text-white font-semibold disabled:bg-gray-300"
                    disabled={!result?.payloads}
                    onClick={() => handleDownload('payloads')}
                >
                    Payloads
                </button>
                <button
                    className="px-4 py-2 rounded bg-blue-500 text-white font-semibold disabled:bg-gray-300"
                    disabled={!result?.instructions}
                    onClick={() => handleDownload('instructions')}
                >
                    Instructions
                </button>
            </div>
        </div>
    );
}

export default TabAttack;
