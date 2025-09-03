// Stripe Checkout Manager for Vibe Beads
// File: public/script/checkout.js

class CheckoutManager {
    constructor() {
        this.isProcessing = false;
        this.cartItems = [];
        this.stripe = null;
        this.elements = null;
        this.cardElement = null;
        this.isStripeInitialized = false;
        this.retryCount = 0;
        this.maxRetries = 3;
        this.requestTimeout = 15000;
        this.sessionId = this.generateSessionId();
        this.apiBaseUrl = this.getApiBaseUrl();
        this.stripePublishableKey = 'pk_test_51S2xLf9qYhHIIRbLy8ZyGmQw2Z36zQaKl2JeksdwUIqe0Lk5rXgjv9Tb8f38KPHDwHuA3qi5ZcV3FQxaGCQCj80I00SoLS7Ycy';
    }

    getApiBaseUrl() {
        // Updated to use your actual Render URL
        return 'https://stripeapi-5re0.onrender.com';
    }

    generateSessionId() {
        return `s_${Date.now().toString(36)}_${Math.random().toString(36).substr(2, 6)}`;
    }

    async init() {
        try {
            this.loadCartItems();
            this.renderCartItems();
            this.updateTotals();
            this.setupEventListeners();

            this.updateStatus('Initializing payment system...', 'info');
            await this.initializeStripe();

            window.addEventListener('cartUpdated', (event) => {
                this.loadCartItems();
                this.renderCartItems();
                this.updateTotals();
            });

            window.addEventListener('beforeunload', (event) => {
                if (this.isProcessing) {
                    event.preventDefault();
                    event.returnValue = 'Payment is being processed. Are you sure you want to leave?';
                }
            });

        } catch (error) {
            console.error('Initialization error:', error);
            this.handleError('Initialization failed', error);
        }
    }

    setupEventListeners() {
        const completeOrderBtn = document.getElementById('complete-order-btn');
        if (completeOrderBtn) {
            completeOrderBtn.replaceWith(completeOrderBtn.cloneNode(true));
            const newBtn = document.getElementById('complete-order-btn');

            newBtn.addEventListener('click', (event) => {
                event.preventDefault();
                this.handleSubmit(event);
            });
        }

        document.addEventListener('keydown', (event) => {
            if (event.key === 'Enter' && event.target.form && !this.isProcessing) {
                event.preventDefault();
                this.handleSubmit(event);
            }
        });
    }

    async initializeStripe() {
        try {
            // Load Stripe.js
            await this.loadStripeJS();

            if (!window.Stripe) {
                throw new Error('Stripe.js not available');
            }

            // Initialize Stripe with your publishable key
            this.stripe = window.Stripe(this.stripePublishableKey);

            // Create Elements
            this.elements = this.stripe.elements({
                appearance: {
                    theme: 'stripe',
                    variables: {
                        colorPrimary: '#8B7355',
                        colorBackground: '#ffffff',
                        colorText: '#2c2c2c',
                        colorDanger: '#df1b41',
                        fontFamily: '"Inter", system-ui, sans-serif',
                        spacingUnit: '4px',
                        borderRadius: '8px'
                    }
                }
            });

            // Create card element
            this.cardElement = this.elements.create('card', {
                style: {
                    base: {
                        fontSize: '16px',
                        color: '#2c2c2c',
                        '::placeholder': {
                            color: '#8B7355',
                        },
                    },
                    invalid: {
                        color: '#df1b41',
                        iconColor: '#df1b41'
                    }
                },
                hidePostalCode: false
            });

            // Mount card element
            this.cardElement.mount('#card-container');

            // Handle real-time validation errors from the card Element
            this.cardElement.on('change', ({error}) => {
                if (error) {
                    this.showError(error.message);
                } else {
                    this.hideError();
                }
            });

            this.isStripeInitialized = true;
            this.updateStatus('Payment system ready', 'success');

        } catch (error) {
            this.updateStatus(`Stripe initialization failed: ${error.message}`, 'error');
            this.isStripeInitialized = false;
            throw error;
        }
    }

    async loadStripeJS() {
        return new Promise((resolve, reject) => {
            if (window.Stripe) {
                resolve();
                return;
            }

            const script = document.createElement('script');
            script.src = 'https://js.stripe.com/v3/';
            script.async = true;

            const timeout = setTimeout(() => {
                script.remove();
                reject(new Error('Stripe.js loading timeout'));
            }, 15000);

            script.onload = () => {
                clearTimeout(timeout);
                resolve();
            };

            script.onerror = () => {
                clearTimeout(timeout);
                script.remove();
                reject(new Error('Failed to load Stripe.js'));
            };

            document.head.appendChild(script);
        });
    }

    async handleSubmit(event) {
        event.preventDefault();

        if (this.isProcessing) {
            return;
        }

        if (this.cartItems.length === 0) {
            this.showError('Your cart is empty. Please add items before checking out.');
            return;
        }

        this.hideError();

        try {
            const formData = this.getFormData();
            const validation = this.validateForm(formData);

            if (!validation.valid) {
                this.showError(validation.message);
                return;
            }

            this.setProcessingState(true);
            const totals = this.updateTotals();

            // Step 1: Create customer if needed
            const customer = await this.createCustomer(formData);

            // Step 2: Create payment intent
            const paymentIntent = await this.createPaymentIntent(totals.total, customer.customerId, formData);

            // Step 3: Confirm payment
            const result = await this.stripe.confirmCardPayment(paymentIntent.clientSecret, {
                payment_method: {
                    card: this.cardElement,
                    billing_details: {
                        name: `${formData.firstName} ${formData.lastName}`,
                        email: formData.email,
                        address: {
                            line1: formData.address,
                            city: formData.city,
                            state: formData.state,
                            postal_code: formData.zipCode,
                            country: formData.country || 'US'
                        }
                    }
                }
            });

            if (result.error) {
                throw new Error(result.error.message);
            }

            if (result.paymentIntent.status === 'succeeded') {
                this.showSuccessPage(result.paymentIntent.id);
                this.clearCart();
            }

        } catch (error) {
            this.handleError('Payment processing failed', error);
        } finally {
            this.setProcessingState(false);
        }
    }

    async createCustomer(formData) {
        try {
            const response = await fetch(`${this.apiBaseUrl}/api/create-customer`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    email: formData.email,
                    name: `${formData.firstName} ${formData.lastName}`,
                    metadata: {
                        session_id: this.sessionId,
                        checkout_timestamp: new Date().toISOString()
                    }
                })
            });

            if (!response.ok) {
                // If customer creation fails, try to get existing customer
                return await this.getExistingCustomer(formData.email);
            }

            return await response.json();
        } catch (error) {
            // Fallback: try to get existing customer
            try {
                return await this.getExistingCustomer(formData.email);
            } catch (fallbackError) {
                console.warn('Customer operations failed, continuing without customer:', error);
                return { customerId: null };
            }
        }
    }

    async getExistingCustomer(email) {
        const response = await fetch(`${this.apiBaseUrl}/api/customer/${encodeURIComponent(email)}`);

        if (!response.ok) {
            throw new Error('Customer not found');
        }

        return await response.json();
    }

    async createPaymentIntent(amount, customerId, formData) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.requestTimeout);

        try {
            const paymentData = {
                amount: amount,
                currency: 'usd',
                metadata: {
                    session_id: this.sessionId,
                    customer_name: `${formData.firstName} ${formData.lastName}`,
                    customer_email: formData.email,
                    order_items: JSON.stringify(this.cartItems.map(item => ({
                        name: item.name,
                        quantity: item.quantity,
                        price: item.price
                    })))
                }
            };

            const response = await fetch(`${this.apiBaseUrl}/api/create-payment-intent`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(paymentData),
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to create payment intent');
            }

            return await response.json();

        } catch (error) {
            clearTimeout(timeoutId);

            if (error.name === 'AbortError') {
                throw new Error('Payment request timed out. Please try again.');
            }

            throw error;
        }
    }

    setProcessingState(processing) {
        this.isProcessing = processing;

        const elements = {
            buttonText: document.getElementById('button-text'),
            buttonSpinner: document.getElementById('button-spinner'),
            completeBtn: document.getElementById('complete-order-btn')
        };

        if (elements.buttonText) {
            elements.buttonText.style.display = processing ? 'none' : 'block';
        }
        if (elements.buttonSpinner) {
            elements.buttonSpinner.style.display = processing ? 'flex' : 'none';
        }
        if (elements.completeBtn) {
            elements.completeBtn.disabled = processing || this.cartItems.length === 0;
            elements.completeBtn.style.opacity = processing ? '0.7' : '1';
            elements.completeBtn.style.cursor = processing ? 'not-allowed' : 'pointer';
        }

        // Disable/enable form inputs
        document.querySelectorAll('input, select').forEach(input => {
            if (processing) {
                input.setAttribute('readonly', 'true');
                input.style.opacity = '0.7';
            } else {
                input.removeAttribute('readonly');
                input.style.opacity = '1';
            }
        });
    }

    loadCartItems() {
        try {
            if (window.cartManager) {
                this.cartItems = window.cartManager.getItems();
            } else {
                const savedCart = localStorage.getItem('vibeBeadsCart');
                this.cartItems = savedCart ? JSON.parse(savedCart) : [];
            }
        } catch (error) {
            console.warn('Failed to load cart items:', error);
            this.cartItems = [];
        }
    }

    saveCartItems() {
        try {
            localStorage.setItem('vibeBeadsCart', JSON.stringify(this.cartItems));
            if (window.cartManager) {
                window.cartManager.cart = this.cartItems;
                window.cartManager.updateCartUI();
            }
        } catch (error) {
            console.warn('Failed to save cart items:', error);
        }
    }

    clearCart() {
        this.cartItems = [];
        this.saveCartItems();
        if (window.cartManager) {
            window.cartManager.clearCart();
        }
    }

    renderCartItems() {
        const cartContainer = document.getElementById('cart-items');
        if (!cartContainer) return;

        if (this.cartItems.length === 0) {
            cartContainer.innerHTML = `
                <div class="empty-cart" role="status">
                    <p>Your cart is empty</p>
                    <button onclick="window.location.href='../index.html'" class="continue-shopping-btn">
                        Continue Shopping
                    </button>
                </div>
            `;
            return;
        }

        const itemsHtml = this.cartItems.map((item, index) => this.renderCartItem(item, index)).join('');
        cartContainer.innerHTML = itemsHtml;
    }

    renderCartItem(item, index) {
        const price = parseFloat(item.price) || 0;
        const quantity = parseInt(item.quantity) || 1;
        const total = price * quantity;

        return `
            <div class="cart-item" data-index="${index}" role="listitem">
                <div class="item-image" aria-hidden="true">${this.escapeHtml(item.image || '🕯️')}</div>
                <div class="item-details">
                    <div class="item-name">${this.escapeHtml(item.name || 'Unknown Item')}</div>
                    <div class="item-price">$${price.toFixed(2)} each</div>
                    <div class="quantity-controls">
                        <button onclick="checkoutManager.updateQuantity(${index}, -1)" 
                                aria-label="Decrease quantity">-</button>
                        <span aria-label="Quantity">${quantity}</span>
                        <button onclick="checkoutManager.updateQuantity(${index}, 1)" 
                                aria-label="Increase quantity">+</button>
                        <button onclick="checkoutManager.removeItem(${index})" 
                                class="remove-btn" aria-label="Remove item">Remove</button>
                    </div>
                </div>
                <div class="item-total">$${total.toFixed(2)}</div>
            </div>
        `;
    }

    updateTotals() {
        const subtotal = this.cartItems.reduce((sum, item) => {
            return sum + ((parseFloat(item.price) || 0) * (parseInt(item.quantity) || 1));
        }, 0);

        const shipping = this.cartItems.length > 0 ? 8.99 : 0;
        const tax = subtotal * 0.08;
        const total = subtotal + shipping + tax;

        this.updateTotalElements(subtotal, shipping, tax, total);

        return { subtotal, shipping, tax, total };
    }

    updateTotalElements(subtotal, shipping, tax, total) {
        const elements = {
            subtotal: document.getElementById('subtotal'),
            shipping: document.getElementById('shipping'),
            tax: document.getElementById('tax'),
            total: document.getElementById('total'),
            buttonText: document.getElementById('button-text')
        };

        if (elements.subtotal) elements.subtotal.textContent = `$${subtotal.toFixed(2)}`;
        if (elements.shipping) elements.shipping.textContent = `$${shipping.toFixed(2)}`;
        if (elements.tax) elements.tax.textContent = `$${tax.toFixed(2)}`;
        if (elements.total) elements.total.textContent = `$${total.toFixed(2)}`;
        if (elements.buttonText && !this.isProcessing) {
            elements.buttonText.textContent = `Complete Order - $${total.toFixed(2)}`;
        }
    }

    getFormData() {
        const formData = {};
        document.querySelectorAll('input, select, textarea').forEach(input => {
            if (input.name) {
                formData[input.name] = input.value.trim();
            }
        });
        return formData;
    }

    validateForm(formData) {
        const requiredFields = ['email', 'firstName', 'lastName', 'address', 'city', 'state', 'zipCode'];
        const missingFields = requiredFields.filter(field => !formData[field]);

        if (missingFields.length > 0) {
            return {
                valid: false,
                message: `Please fill in required fields: ${missingFields.join(', ')}`
            };
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
            return { valid: false, message: 'Please enter a valid email address' };
        }

        if (formData.zipCode && !/^\d{5}(-\d{4})?$/.test(formData.zipCode)) {
            return { valid: false, message: 'Please enter a valid ZIP code' };
        }

        return { valid: true };
    }

    showError(message) {
        const errorElement = document.getElementById('error-message');
        const errorText = document.getElementById('error-text');

        if (errorElement && errorText) {
            errorText.textContent = this.escapeHtml(message);
            errorElement.style.display = 'block';
            errorElement.setAttribute('role', 'alert');
            errorElement.scrollIntoView({ behavior: 'smooth', block: 'center' });

            setTimeout(() => this.hideError(), 15000);
        }
    }

    hideError() {
        const errorElement = document.getElementById('error-message');
        if (errorElement) {
            errorElement.style.display = 'none';
            errorElement.removeAttribute('role');
        }
    }

    showSuccessPage(paymentId) {
        const checkoutContent = document.getElementById('checkout-content');
        const successMessage = document.getElementById('success-message');
        const paymentIdText = document.getElementById('payment-id-text');

        if (checkoutContent) checkoutContent.style.display = 'none';
        if (successMessage) successMessage.style.display = 'block';
        if (paymentIdText) paymentIdText.textContent = this.escapeHtml(paymentId);

        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    updateStatus(message, type = 'info') {
        console.log(`Status (${type}):`, message);

        const statusElement = document.getElementById('square-status');
        if (statusElement) {
            statusElement.textContent = message;
            statusElement.className = `square-status status-${type}`;

            if (type === 'success') {
                setTimeout(() => {
                    if (statusElement.textContent === message) {
                        statusElement.textContent = '';
                        statusElement.className = 'square-status';
                    }
                }, 5000);
            }
        }
    }

    handleError(context, error) {
        console.error(`${context}:`, error);
        const message = error.message || 'An unexpected error occurred. Please try again.';
        this.showError(message);
        this.updateStatus(`Error: ${message}`, 'error');
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    updateQuantity(index, change) {
        if (index < 0 || index >= this.cartItems.length) return;

        const newQuantity = Math.max(0, (parseInt(this.cartItems[index].quantity) || 1) + change);

        if (newQuantity === 0) {
            this.removeItem(index);
        } else {
            this.cartItems[index].quantity = newQuantity;
            this.saveCartItems();
            this.renderCartItems();
            this.updateTotals();
        }
    }

    removeItem(index) {
        if (index < 0 || index >= this.cartItems.length) return;

        this.cartItems.splice(index, 1);
        this.saveCartItems();
        this.renderCartItems();
        this.updateTotals();

        if (window.cartManager) {
            window.cartManager.cart = this.cartItems;
            window.cartManager.updateCartUI();
        }
    }
}

// Initialize checkout manager
const checkoutManager = new CheckoutManager();

document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, initializing Stripe checkout manager...');
    checkoutManager.init().then(() => {
        console.log('Stripe checkout manager initialized successfully');
    }).catch(error => {
        console.error('Failed to initialize checkout manager:', error);
    });
});

// Make methods globally available for onclick handlers
window.checkoutManager = checkoutManager;
