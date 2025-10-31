import React, { useState } from 'react';
import { FILE_TYPE } from './types';

function TabDefend() {
    // Gom 3 file upload vào 1 object
    const [uploadedFiles, setUploadedFiles] = useState({
        domain: null,
        payloads: null,
        instructions: null
    });

    const [isGenerating, setIsGenerating] = useState(false);
    const [rulesGenerated, setRulesGenerated] = useState(null);

    const handleFileChange = (e, type) => {
        const file = e.target.files[0];
        let key = null;
        switch (type) {
            case FILE_TYPE.DOMAIN_INFO:
                key = 'domain';
                break;
            case FILE_TYPE.PAYLOADS:
                key = 'payloads';
                break;
            case FILE_TYPE.INSTRUCTIONS:
                key = 'instructions';
                break;
            default:
                break;
        }
        if (key) {
            setUploadedFiles(prev => ({ ...prev, [key]: file }));
        }
    };

    const handleDrop = (e, type) => {
        e.preventDefault();
        const file = e.dataTransfer.files[0];
        let key = null;
        switch (type) {
            case FILE_TYPE.DOMAIN_INFO:
                key = 'domain';
                break;
            case FILE_TYPE.PAYLOADS:
                key = 'payloads';
                break;
            case FILE_TYPE.INSTRUCTIONS:
                key = 'instructions';
                break;
            default:
                break;
        }
        if (key) {
            setUploadedFiles(prev => ({ ...prev, [key]: file }));
        }
    };

    const handleDragOver = (e) => {
        e.preventDefault();
    };

    const handleGenerateRules = async () => {
        setIsGenerating(true);
        try {
            await new Promise(resolve => setTimeout(resolve, 2000)); // Giả lập thời gian chờ
            // Giả lập sinh rules cho WAF
            const generatedRules = {
                rules: [
                    { id: 1, pattern: "sql_injection", action: "block" },
                    { id: 2, pattern: "xss_attack", action: "block" },
                    { id: 3, pattern: "path_traversal", action: "block" }
                ]
            };
            setRulesGenerated(generatedRules);
        } finally {
            setIsGenerating(false);
        }
    };

    const handleDownload = () => {
        // Download nội dung rules đã sinh
        const data = JSON.stringify(rulesGenerated, null, 2);
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'DefendInstructions.json';
        a.click();
        URL.revokeObjectURL(url);
    };

    const uploadBox = (type, label) => (
        <div className="flex flex-col items-center w-1/3">
            <label
                className="border-2 border-dashed border-gray-400 rounded-lg w-full h-24 flex items-center justify-center cursor-pointer bg-gray-50 hover:bg-gray-100"
                onDrop={e => handleDrop(e, type)}
                onDragOver={handleDragOver}
            >
                <input
                    type="file"
                    className="hidden"
                    onChange={e => handleFileChange(e, type)}
                />
                <span className="text-gray-500">Drag or click to upload</span>
            </label>
            <div className="mt-2 text-sm font-semibold text-gray-700">{label}</div>
            {/* Hiển thị tên file đã upload nếu có */}
            {(() => {
                let key = null;
                switch (type) {
                    case FILE_TYPE.DOMAIN_INFO:
                        key = 'domain';
                        break;
                    case FILE_TYPE.PAYLOADS:
                        key = 'payloads';
                        break;
                    case FILE_TYPE.INSTRUCTIONS:
                        key = 'instructions';
                        break;
                    default:
                        break;
                }
                return key && uploadedFiles[key] ? (
                    <div className="mt-1 text-xs text-green-600">{uploadedFiles[key].name}</div>
                ) : null;
            })()}
        </div>
    );

    return (
        <div className="space-y-8">
            <div className="flex gap-4">
                {uploadBox(FILE_TYPE.DOMAIN_INFO, 'DomainInfo.json')}
                {uploadBox(FILE_TYPE.PAYLOADS, 'Payloads.json')}
                {uploadBox(FILE_TYPE.INSTRUCTIONS, 'Instructions.json')}
            </div>
            <button
                className="w-full bg-blue-600 text-white py-3 rounded font-bold text-lg hover:bg-blue-700 disabled:bg-gray-300"
                onClick={handleGenerateRules}
                disabled={!(uploadedFiles.domain && uploadedFiles.payloads && uploadedFiles.instructions) || isGenerating}
            >
                {isGenerating ? 'Đang sinh rules...' : 'Generate Rules'}
            </button>
            <div className="flex justify-center">
                <button
                    className="w-1/2 bg-green-600 text-white py-3 rounded font-bold text-lg disabled:bg-gray-300"
                    disabled={!rulesGenerated}
                    onClick={handleDownload}
                >
                    Tải DefendInstructions.json
                </button>
            </div>
            {rulesGenerated && (
                <pre className="bg-gray-100 p-4 mt-4 rounded text-xs overflow-x-auto">
                    {JSON.stringify(rulesGenerated, null, 2)}
                </pre>
            )}
        </div>
    );
}

export default TabDefend;
