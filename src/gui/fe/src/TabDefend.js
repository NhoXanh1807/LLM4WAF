import React, { useState } from 'react';

function TabDefend() {
    const [uploadedFiles, setUploadedFiles] = useState({
        domain: null,
        payloads: null,
        instructions: null,
    });
    const [rulesGenerated, setRulesGenerated] = useState(false);

    const handleFileChange = (e, type) => {
        const file = e.target.files[0];
        setUploadedFiles(prev => ({ ...prev, [type]: file }));
    };

    const handleDrop = (e, type) => {
        e.preventDefault();
        const file = e.dataTransfer.files[0];
        setUploadedFiles(prev => ({ ...prev, [type]: file }));
    };

    const handleDragOver = (e) => {
        e.preventDefault();
    };

    const handleGenerateRules = () => {
        setRulesGenerated(true);
    };

    const handleDownload = () => {
        // Dummy download logic
        const data = 'Nội dung file DefendInstructions.json';
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
            {uploadedFiles[type] && (
                <div className="mt-1 text-xs text-green-600">{uploadedFiles[type].name}</div>
            )}
        </div>
    );

    return (
        <div className="space-y-8">
            <div className="flex gap-4">
                {uploadBox('domain', 'DomainInfo.json')}
                {uploadBox('payloads', 'Payloads.json')}
                {uploadBox('instructions', 'Instructions.json')}
            </div>
            <button
                className="w-full bg-blue-600 text-white py-3 rounded font-bold text-lg hover:bg-blue-700"
                onClick={handleGenerateRules}
                disabled={!(uploadedFiles.domain && uploadedFiles.payloads && uploadedFiles.instructions)}
            >
                Generate Rules
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
        </div>
    );
}

export default TabDefend;
