
const BASE_API_URL = process.env.REACT_APP_API_URL;
const Call = async (path, method, body = null, headers = {}) => {
    var options = {
        method: method,
        credentials: "include",
        headers: {
            ...headers,
        },
        body: body ? JSON.stringify(body) : null,
    };
    const result = await fetch(`${BASE_API_URL}${path}`, options);
    return result;
};

export const Services = {
    attack: async (domain, attack_type, num_payloads = 5, payloads_history = []) => {
        return Call("/attack", "POST", { domain, attack_type, num_payloads, payloads_history }, { "Content-Type": "application/json" });
    },
    defend: async (waf_info, bypassed_payloads, bypassed_instructions) => {
        return Call("/defend", "POST", { waf_info, bypassed_payloads, bypassed_instructions }, { "Content-Type": "application/json" });
    },
    retest: async (bypassed_payloads) => {
        return Call("/retest", "POST", { bypassed_payloads }, { "Content-Type": "application/json" });
    }
}