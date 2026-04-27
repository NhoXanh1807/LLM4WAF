
const BASE_API_URL = process.env.REACT_APP_API_URL;
const Call = async (path, method, body = null, headers = {}) => {
    var options = {
        method: method,
        credentials: "include",
        headers: {
            ...headers,
            "ngrok-skip-browser-warning": "true",
        },
        body: body ? JSON.stringify(body) : null,
    };
    const result = await fetch(`${BASE_API_URL}${path}`, options);
    return result;
};

export const Services = {
    apiDetectWAF: async (domain) => {
        // /api/detect_waf expects { domain }
        return Call("/detect_waf", "POST", { domain }, { "Content-Type": "application/json" });
    },
    apiGeneratePayloadRandom: async (waf_name, attack_type, num_payloads, payloads_history = []) => {
        // /api/generate_payload expects { waf_name, attack_type, num_payloads }
        return Call("/generate_payload", "POST", { waf_name, attack_type, num_payloads, payloads_history }, { "Content-Type": "application/json" });
    },
    apiGeneratePayloadAdaptive: async (waf_name, attack_type, num_payloads, payloads_history) => {
        // /api/generate_payload expects { waf_name, attack_type, num_payloads, payloads_history }
        return Call("/generate_payload", "POST", { waf_name, attack_type, num_payloads, payloads_history }, { "Content-Type": "application/json" });
    },
    apiTestAttack: async (domain, payloads = []) => {
        // /api/test_attack expects { domain, payloads }
        return Call("/test_attack", "POST", { domain, payloads }, { "Content-Type": "application/json" });
    },
    apiDefend: async (waf_name, payloads, existing_rules = null, llm_provider = "openai") => {
        // /api/defend expects { waf_name, payloads, existing_rules, llm_provider }
        return Call("/defend", "POST", { waf_name, payloads, existing_rules, llm_provider }, { "Content-Type": "application/json" });
    },
}