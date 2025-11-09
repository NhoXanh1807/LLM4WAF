import React, { useState } from 'react';
import BypassedDataTable from './BypassedDataTable';
import { Services } from './services';

function App() {
  const [activeTab, setActiveTab] = useState('Attack');
  const [wafInfo, setWafInfo] = useState(null);
  const [payloads, setPayloads] = useState([]);
  const [instructions, setInstructions] = useState([]);
  const [bypassedIndexs, setBypassedIndexs] = useState([]);
  const [domain, setDomain] = useState('');
  const [attackType, setAttackType] = useState('XSS');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [rulesGenerated, setRulesGenerated] = useState(null);
  const [rawResponse, setRawResponse] = useState(null);
  const [showRaw, setShowRaw] = useState(false);
  const [isDefending, setIsDefending] = useState(false);

  // Helper download
  const handleDownload = (filename) => {
    let data = null;
    if (filename === "waf")
      data = wafInfo;
    else if (filename === "payloads")
      data = payloads;
    else if (filename === "instructions")
      data = instructions;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename + '.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-gray-50 p-8 items-center flex flex-col">
      <div className="flex justify-center gap-2">
        <button
          className={`px-20 py-5 rounded-t font-bold border-b-2 ${activeTab === 'Attack' ? 'border-green-500 text-red-600 bg-white' : 'border-transparent text-gray-500 bg-gray-100'}`}
          onClick={() => setActiveTab('Attack')}
        >
          Attack
        </button>
        <button
          className={`px-20 py-5 rounded-t font-bold border-b-2 ${activeTab === 'Defend' ? 'border-blue-500 text-blue-600 bg-white' : 'border-transparent text-gray-500 bg-gray-100'}`}
          onClick={() => setActiveTab('Defend')}
        >
          Defend
        </button>
      </div>
      <div className="flex flex-col bg-white p-6 rounded shadow w-full max-w-screen">
        {activeTab === 'Attack' && (
          <>
            {/* Form nhập domain và attack type */}
            <form className="flex items-center space-x-4 mb-4" onSubmit={async (e) => {
              e.preventDefault();
              setIsSubmitting(true);
              try {
                const res = await Services.attack(domain, attackType);
                const data = res.ok ? await res.json() : null;
                setWafInfo(data?.waf_info);
                setPayloads(data?.payloads || []);
                setInstructions(data?.instructions || []);
                setRawResponse(data);
              } finally {
                setIsSubmitting(false);
              }
            }}>
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
                Attack
              </button>
            </form>
            {/* 3 nút download */}
            <div className="flex space-x-4 mb-4">
              <button
                className="px-4 py-2 rounded bg-green-500 text-white font-semibold disabled:bg-gray-300"
                disabled={!wafInfo}
                onClick={() => handleDownload('waf')}
              >
                WafInfo &#x25BC;
              </button>
              <button
                className="px-4 py-2 rounded bg-red-500 text-white font-semibold disabled:bg-gray-300"
                disabled={!payloads || !payloads.length}
                onClick={() => handleDownload('payloads')}
              >
                Payloads &#x25BC;
              </button>
              <button
                className="px-4 py-2 rounded bg-blue-500 text-white font-semibold disabled:bg-gray-300"
                disabled={!instructions || !instructions.length}
                onClick={() => handleDownload('instructions')}
              >
                Instructions &#x25BC;
              </button>
            </div>
            {/* Bảng chọn */}
            <BypassedDataTable
              wafInfo={wafInfo}
              payloads={payloads}
              instructions={instructions}
              bypassedIndexes={bypassedIndexs}
              setBypassedIndexes={setBypassedIndexs}
            />
            {/* Toggle view raw response */}
            <div className="my-4 flex flex-col items-start">
              <button
                className="px-3 py-1 rounded bg-gray-300 hover:bg-gray-400 text-sm font-semibold mb-2"
                onClick={() => setShowRaw(!showRaw)}
                type="button"
              >
                {showRaw ? 'Ẩn Raw Response' : 'Hiện Raw Response'}
              </button>
              {showRaw && rawResponse && (
                <textarea
                  className="w-full h-32 border rounded p-2 text-xs bg-gray-50"
                  value={typeof rawResponse === 'string' ? rawResponse : JSON.stringify(rawResponse, null, 2)}
                  readOnly
                  placeholder="Raw response sẽ hiển thị ở đây..."
                />
              )}
            </div>
          </>
        )}
        {activeTab === 'Defend' && (
          <>
            {/* Bảng chọn */}
            <BypassedDataTable
              wafInfo={wafInfo}
              payloads={payloads}
              instructions={instructions}
              bypassedIndexes={bypassedIndexs}
              setBypassedIndexes={setBypassedIndexs}
            />
            {/* Nút generate rules */}
            <button
              className="w-full bg-blue-600 text-white py-3 rounded font-bold text-lg hover:bg-blue-700 mt-4 disabled:bg-gray-300"
              onClick={async () => {
                setIsDefending(true);
                try {
                  const selectedPayloads = Array.isArray(payloads) ? bypassedIndexs.map(i => payloads[i]) : [];
                  const selectedInstructions = Array.isArray(instructions) ? bypassedIndexs.map(i => instructions[i]) : [];
                  const res = await Services.defend(wafInfo, selectedPayloads, selectedInstructions);
                  const data = res.ok ? await res.json() : null;
                  setRawResponse(data);
                  setRulesGenerated(data?.rules);
                } finally {
                  setIsDefending(false);
                }
              }}
              disabled={isDefending}
            >
              Defend
            </button>
            {/* Toggle view raw response */}
            <div className="my-4 flex flex-col items-start">
              <button
                className="px-3 py-1 rounded bg-gray-300 hover:bg-gray-400 text-sm font-semibold mb-2"
                onClick={() => setShowRaw(!showRaw)}
                type="button"
              >
                {showRaw ? 'Ẩn Raw Response' : 'Hiện Raw Response'}
              </button>
              {showRaw && rawResponse && (
                <textarea
                  className="w-full h-32 border rounded p-2 text-xs bg-gray-50"
                  value={typeof rawResponse === 'string' ? rawResponse : JSON.stringify(rawResponse, null, 2)}
                  readOnly
                  placeholder="Raw response sẽ hiển thị ở đây..."
                />
              )}
            </div>
            {/* Bảng kết quả rules */}
            {Array.isArray(rulesGenerated) && (
              <div className="overflow-x-auto mt-8">
                <table className="min-w-full table-auto border-collapse">
                  <thead>
                    <tr>
                      <th className="text-left font-bold p-2 border-b">Rule</th>
                      <th className="text-left font-bold p-2 border-b">Instructions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rulesGenerated.map((item, idx) => (
                      <tr key={idx} className={idx % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                        <td className="align-top p-3 border-t w-1/2">
                          <pre className="whitespace-pre-wrap text-sm m-0 font-mono">{item.rule}</pre>
                        </td>
                        <td className="align-top p-3 border-t w-1/2">
                          <pre className="whitespace-pre-wrap text-sm m-0">{item.instructions}</pre>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

export default App;
