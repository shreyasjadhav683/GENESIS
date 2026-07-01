
export const setupAuthInterceptor = () => {
    const { fetch: originalFetch } = window;

    window.fetch = async (...args) => {
        try {
            const response = await originalFetch(...args);

 
            if (response.status === 401 || response.status === 403) {
                // Token expired, invalid, or forbidden
                console.warn(`Session expired (${response.status}). Redirecting to login...`);
                localStorage.removeItem('token');
                
                // Only redirect if not already on the login page to avoid loops
                if (!window.location.pathname.includes('/login')) {
                    window.location.href = '/login';
                }
            }

            return response;
        } catch (error) {
            throw error;
        }
    };
};
