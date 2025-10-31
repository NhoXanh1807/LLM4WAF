import React, { useState } from 'react';
import TabAttack from './TabAttack';
import TabDefend from './TabDefend';

function App() {
  const [activeTab, setActiveTab] = useState('Attack');

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
      <div className="flex flex-col bg-white p-6 rounded shadow w-full max-w-2xl">
        {activeTab === 'Attack' && <TabAttack />}
        {activeTab === 'Defend' && <TabDefend />}
      </div>
    </div>
  );
}

export default App;
