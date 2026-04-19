
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
    // // Old services (giữ nguyên)
    // attack: async (domain, attack_type, num_payloads = 5, payloads_history = []) => {
    //     return Call("/attack", "POST", { domain, attack_type, num_payloads, payloads_history }, { "Content-Type": "application/json" });
    // },
    // defend: async (waf_info, bypassed_payloads, num_rules = 3) => {
    //     return Call("/defend", "POST", { waf_info, bypassed_payloads, num_rules }, { "Content-Type": "application/json" });
    // },
    // retest: async (bypassed_payloads) => {
    //     return Call("/retest", "POST", { bypassed_payloads }, { "Content-Type": "application/json" });
    // },
    // detectWAF: async (domain) => {
    //     return Call("/detect-waf", "POST", { domain }, { "Content-Type": "application/json" });
    // },
    // defend: async (waf_info, bypassed_payloads, num_rules = 3, existing_rules = null) => {
    //     return Call("/defend", "POST", { waf_info, bypassed_payloads, num_rules, existing_rules }, { "Content-Type": "application/json" });
    // },

    // Các service mới tương ứng backend
    apiDetectWAF: async (domain) => {
        // /api/detect_waf expects { domain }
        return Call("/detect_waf", "POST", { domain }, { "Content-Type": "application/json" });
    },
    apiGeneratePayload: async (waf_name, attack_type, num_payloads = 5, payloads_history = []) => {
        // /api/generate_payload expects { waf_name, attack_type, num_payloads, payloads_history }
        return Call("/generate_payload", "POST", { waf_name, attack_type, num_payloads, payloads_history }, { "Content-Type": "application/json" });
    },
    apiAttackDVWA: async (domain, payloads = []) => {
        // /api/attack_dvwa expects { domain, payloads }
        return Call("/attack_dvwa", "POST", { domain, payloads }, { "Content-Type": "application/json" });
    },
    apiDefend: async (waf_name, payloads, num_rules = 3) => {
        // /api/defend expects { waf_name, payloads, num_rules }
        return Call("/defend", "POST", { waf_name, payloads, num_rules }, { "Content-Type": "application/json" });
    },
}