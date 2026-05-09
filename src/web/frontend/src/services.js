
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

const JSON_HEADERS = { "Content-Type": "application/json" };

export const Services = {
    apiDetectWAF: async (domain) => {
        return Call("/attack/1-detect-waf", "POST", { domain }, JSON_HEADERS);
    },
    apiGeneratePayload: async (waf_name, attack_type, num_payloads, payloads_history = []) => {
        return Call(
            "/attack/2-generate-payload",
            "POST",
            { waf_name, attack_type, num_payloads, payloads_history },
            JSON_HEADERS,
        );
    },
    apiTestAttack: async (domain, payloads = [], check_harmful = true) => {
        return Call("/attack/3-test", "POST", { domain, payloads, check_harmful }, JSON_HEADERS);
    },

    apiDefendClustering: async (attack_type, payloads = []) => {
        return Call("/defend/1-clustering", "POST", { attack_type, payloads }, JSON_HEADERS);
    },

    apiDefendRagRetrieve: async (waf_name, attack_type, payloads = []) => {
        return Call("/defend/2-rag-retrieve", "POST", { waf_name, attack_type, payloads }, JSON_HEADERS);
    },

    apiDefendGenerateRules: async (waf_name, clusters = [], rag_context = "") => {
        return Call("/defend/3-generate-rules", "POST", { waf_name, clusters, rag_context }, JSON_HEADERS);
    },

    apiDefendValidateRules: async (generated_rules = []) => {
        return Call("/defend/4-validate-rules", "POST", { generated_rules }, JSON_HEADERS);
    },

    apiDefendRetryInvalidRules: async (waf_name, invalid_rules = []) => {
        return Call("/defend/5-retry-invalid-rules", "POST", { waf_name, invalid_rules }, JSON_HEADERS);
    },

    apiDefendRefineRules: async (waf_name, valid_rules = [], existing_rules = []) => {
        return Call("/defend/6-refine-rules", "POST", { waf_name, valid_rules, existing_rules }, JSON_HEADERS);
    },
}