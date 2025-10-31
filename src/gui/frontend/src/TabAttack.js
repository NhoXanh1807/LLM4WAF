import React, { useState } from 'react';
import { FILE_TYPE } from './types';


function TabAttack() {
    const [attackType, setAttackType] = useState('XSS');
    const [domain, setDomain] = useState('');
    const [logConsole, setLogConsole] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [resultDomainInfo, setResultDomainInfo] = useState(null);
    const [resultPayloads, setResultPayloads] = useState(null);
    const [resultInstructions, setResultInstructions] = useState(null);

    const log = (msg) => setLogConsole((prev) => prev + '\n' + msg);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setIsSubmitting(true);
        try {
            await new Promise(resolve => setTimeout(resolve, 2000)); // Giả lập thời gian chờ
            log(`Đang kiểm tra domain: ${domain} với kiểu tấn công: ${attackType}...`);
            setResultDomainInfo({ domain_name: domain, attack_type: attackType, status: "completed" });
            setResultPayloads([{ payload: "<script>alert(1)</script>" }])
            setResultInstructions([{ instruction: "1. Open the browser console\n2. Paste the payload\n3. Press Enter" }])
            log(`Hoàn tất!`);
        }
        finally {
            setIsSubmitting(false);
        }
    };

    const handleDownload = async (FILE_TYPE) => {
        await new Promise(resolve => setTimeout(resolve, 2000)); // Giả lập thời gian chờ
        // Dummy download logic
        let data = '';
        switch (FILE_TYPE) {
            case FILE_TYPE.DOMAIN_INFO:
                data = JSON.stringify(resultDomainInfo, null, 2);
                break;
            case FILE_TYPE.PAYLOADS:
                data = JSON.stringify(resultPayloads, null, 2);
                break;
            case FILE_TYPE.INSTRUCTIONS:
                data = JSON.stringify(resultInstructions, null, 2);
                break;
            default:
                break;
        }
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = FILE_TYPE;
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
                    disabled={isSubmitting}
                    className="bg-red-500 text-white px-4 py-2 rounded font-bold hover:bg-red-600 disabled:bg-gray-300"
                >
                    Submit
                </button>
            </form>
            <textarea
                className="w-full h-32 border rounded p-2 text-sm bg-gray-50"
                value={logConsole}
                readOnly
                placeholder="Log sẽ hiển thị ở đây..."
            />
            <div className="flex space-x-4">
                <button
                    className="px-4 py-2 rounded bg-green-500 text-white font-semibold disabled:bg-gray-300"
                    disabled={!resultDomainInfo}
                    onClick={() => handleDownload(FILE_TYPE.DOMAIN_INFO)}
                >
                    DomainInfo.json
                </button>
                <button
                    className="px-4 py-2 rounded bg-red-500 text-white font-semibold disabled:bg-gray-300"
                    disabled={!resultPayloads}
                    onClick={() => handleDownload(FILE_TYPE.PAYLOADS)}
                >
                    Payloads.json
                </button>
                <button
                    className="px-4 py-2 rounded bg-blue-500 text-white font-semibold disabled:bg-gray-300"
                    disabled={!resultInstructions}
                    onClick={() => handleDownload(FILE_TYPE.INSTRUCTIONS)}
                >
                    Instructions.json
                </button>
            </div>
        </div>
    );
}

export default TabAttack;
