import React from 'react';

function BypassedDataTable({ wafInfo, payloads, instructions, bypassedIndexes, setBypassedIndexes }) {
    // Xác định dữ liệu hiển thị (payloads là mảng các object)
    const data = Array.isArray(payloads) ? payloads : [];

    // Lấy instructions cho từng dòng nếu có
    const getInstructions = idx => {
        if (Array.isArray(instructions) && instructions[idx]) {
            if (Array.isArray(instructions[idx].instruction)) {
                return instructions[idx].instruction.join(' | ');
            }
            return instructions[idx].instruction || JSON.stringify(instructions[idx]);
        }
        return '';
    };

    // Xử lý chọn/bỏ index
    const handleToggleIndex = idx => {
        if (bypassedIndexes.includes(idx)) {
            setBypassedIndexes(bypassedIndexes.filter(i => i !== idx));
        } else {
            setBypassedIndexes([...bypassedIndexes, idx]);
        }
    };

    return (
        <div className="overflow-x-auto">
            {/* WafInfo hiển thị ở đầu bảng */}
            <div className="mb-4">
                <h3 className="font-bold mb-2">WafInfo</h3>
                <textarea
                    className="w-full h-24 border rounded p-2 text-sm bg-gray-50"
                    value={wafInfo ? (typeof wafInfo === 'string' ? wafInfo : JSON.stringify(wafInfo, null, 2)) : ''}
                    readOnly
                />
            </div>
            <table className="min-w-full border rounded bg-gray-50 text-sm">
                <thead>
                    <tr className="bg-gray-200">
                        <th className="px-2 py-1">#</th>
                        <th className="px-2 py-1">Type</th>
                        <th className="px-2 py-1">Payload</th>
                        <th className="px-2 py-1">Instruction</th>
                        <th className="px-2 py-1">Is Bypassed</th>
                    </tr>
                </thead>
                <tbody>
                    {data.map((item, idx) => (
                        <tr key={idx}>
                            <td className="border px-2 py-1 text-center">{idx + 1}</td>
                            <td className="border px-2 py-1">{item.attack_type || ''}</td>
                            <td className="border px-2 py-1 break-all">{item.payload || JSON.stringify(item)}</td>
                            <td className="border px-2 py-1 break-all">{getInstructions(idx)}</td>
                            <td className="border px-2 py-1 text-center">
                                <input
                                className='size-8'
                                    type="checkbox"
                                    checked={bypassedIndexes.includes(idx)}
                                    onChange={() => handleToggleIndex(idx)}
                                />
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

export default BypassedDataTable;
