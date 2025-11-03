
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
    detectWAF: async (domain) => {
        return Call("/detect/waf", "POST", { domain: domain }, { "Content-Type": "application/json" });
    }
}