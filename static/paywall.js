/**
 * SatGateway Paywall SDK
 * 
 * Drop this script on any page to add a Lightning paywall.
 * 
 * Usage:
 *   <script src="/static/paywall.js" 
 *           data-amount="100"
 *           data-resource="/api/premium"
 *           data-container="paywall-container">
 *   </script>
 */
(function() {
    const script = document.currentScript;
    const amount = parseInt(script.dataset.amount || '100');
    const resource = script.dataset.resource || window.location.pathname;
    const containerId = script.dataset.container || 'satgateway-paywall';
    const gatewayUrl = script.dataset.gateway || '';
    const apiKey = script.dataset.apiKey || '';

    // Create container if it doesn't exist
    let container = document.getElementById(containerId);
    if (!container) {
        container = document.createElement('div');
        container.id = containerId;
        script.parentNode.insertBefore(container, script.nextSibling);
    }

    const baseUrl = gatewayUrl || window.location.origin;

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    async function createPayment() {
        const headers = {'Content-Type': 'application/json'};
        if (apiKey) {
            headers['X-API-Key'] = apiKey;
        }
        const res = await fetch(`${baseUrl}/payments/invoice`, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({
                amount_sats: amount,
                description: `Access to ${resource}`,
                resource_url: resource
            })
        });
        return res.json();
    }

    async function verifyPayment(paymentId) {
        const res = await fetch(`${baseUrl}/payments/verify/${paymentId}`);
        return res.json();
    }

    async function loadResource(paymentId) {
        const res = await fetch(resource, {
            headers: {
                'X-Payment-ID': paymentId
            }
        });
        if (res.status === 402) {
            // Still need to pay
            return {paid: false, data: await res.json()};
        }
        return {paid: true, data: await res.json()};
    }

    function renderPaywall(payment) {
        const safeInvoice = escapeHtml(payment.invoice);
        const safeAmount = escapeHtml(String(payment.amount_sats));
        container.innerHTML = `
            <div style="font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 1.5rem; text-align: center; max-width: 360px; margin: 0 auto;">
                <h3 style="margin: 0 0 0.5rem; color: #F7931A;">⚡ Lightning Paywall</h3>
                <div style="font-size: 2rem; font-weight: 700; margin: 0.5rem 0;">${safeAmount} <span style="font-size: 1rem; color: #8b949e;">sats</span></div>
                <div style="margin: 1rem 0;">
                    <img src="${baseUrl}/payments/qr/${payment.payment_id}" alt="QR Code" style="max-width: 200px; border-radius: 8px;">
                </div>
                <button onclick="copyInvoice('${escapeHtml(payment.invoice)}')" style="background: #F7931A; color: #000; border: none; padding: 0.6rem 1.2rem; border-radius: 8px; font-weight: 600; cursor: pointer;">Copy Invoice</button>
                <div style="font-size: 0.75rem; color: #484f58; word-break: break-all; margin-top: 1rem;">${safeInvoice}</div>
                <div id="sg-status" style="margin-top: 1rem; padding: 0.5rem; border-radius: 8px; font-size: 0.875rem; background: rgba(247,147,26,0.1); color: #F7931A;">⏳ Waiting for payment...</div>
            </div>
        `;
    }

    function renderContent(data) {
        const safeData = escapeHtml(JSON.stringify(data, null, 2));
        container.innerHTML = `
            <div style="font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 1.5rem; text-align: center; max-width: 360px; margin: 0 auto;">
                <h3 style="margin: 0 0 0.5rem; color: #22c55e;">✅ Payment Confirmed</h3>
                <pre style="text-align: left; background: #0d1117; padding: 1rem; border-radius: 8px; overflow-x: auto; font-size: 0.8rem; color: #e6edf3;">${safeData}</pre>
            </div>
        `;
    }

    window.copyInvoice = function(invoice) {
        navigator.clipboard.writeText(invoice);
        event.target.textContent = 'Copied!';
    };

    async function init() {
        // Check if we already paid (cookie)
        const existingId = document.cookie.split('; ').find(r => r.startsWith('sg_payment_id='));
        if (existingId) {
            const paymentId = existingId.split('=')[1];
            const result = await loadResource(paymentId);
            if (result.paid) {
                renderContent(result.data);
                return;
            }
        }

        // Create new payment
        const payment = await createPayment();
        if (payment.error) {
            container.innerHTML = `<div style="color:#f85149;text-align:center;">Error: ${escapeHtml(payment.error || 'Unable to create invoice')}</div>`;
            return;
        }
        renderPaywall(payment);

        // Poll for payment
        const interval = setInterval(async () => {
            const status = await verifyPayment(payment.payment_id);
            if (status.paid) {
                clearInterval(interval);
                document.getElementById('sg-status').textContent = '✅ Paid! Loading content...';
                document.getElementById('sg-status').style.background = 'rgba(35,197,94,0.1)';
                document.getElementById('sg-status').style.color = '#22c55e';

                // Try loading the resource
                const result = await loadResource(payment.payment_id);
                if (result.paid) {
                    renderContent(result.data);
                }
            } else if (status.expired) {
                clearInterval(interval);
                document.getElementById('sg-status').textContent = '❌ Expired. Refresh to try again.';
            }
        }, 2000);
    }

    init();
})();
