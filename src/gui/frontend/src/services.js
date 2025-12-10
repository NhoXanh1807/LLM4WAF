
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
<<<<<<< Updated upstream
    detectWAF: async (domain) => {
        return Call("/detect/waf", "POST", { domain: domain }, { "Content-Type": "application/json" });
=======
    attack: async (domain, attack_type, num) => {
        return Call("/attack", "POST", { domain, attack_type, num }, { "Content-Type": "application/json" });
    },
    defend: async (waf_info, bypassed_payloads, bypassed_instructions) => {
        return Call("/defend", "POST", { waf_info, bypassed_payloads, bypassed_instructions }, { "Content-Type": "application/json" });
>>>>>>> Stashed changes
    }
}