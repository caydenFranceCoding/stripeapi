const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// Security middleware
app.use(helmet());

// Simplified CORS configuration that should work reliably
app.use(cors({
  origin: [
    'http://localhost:3000',
    'http://localhost:8080',
    'https://vibebeads.net',
    'https://www.vibebeads.net'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  optionsSuccessStatus: 200 // Some legacy browsers choke on 204
}));

// Handle preflight requests explicitly
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With');
  res.header('Access-Control-Allow-Credentials', true);
  res.sendStatus(200);
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Stripe webhook middleware (raw body needed for signature verification)
app.use('/api/webhooks/stripe', express.raw({ type: 'application/json' }));

// JSON middleware for other routes
app.use(express.json({ limit: '10mb' }));

// Initialize Stripe
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Webhook endpoint secret
const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    cors_origins: [
      'http://localhost:3000',
      'http://localhost:8080', 
      'https://vibebeads.net',
      'https://www.vibebeads.net'
    ]
  });
});

// Test CORS endpoint
app.get('/api/test-cors', (req, res) => {
  res.json({
    message: 'CORS is working!',
    origin: req.headers.origin,
    timestamp: new Date().toISOString()
  });
});

// Create payment intent
app.post('/api/create-payment-intent', async (req, res) => {
  try {
    console.log('Create payment intent request from origin:', req.headers.origin);
    const { amount, currency = 'usd', metadata = {} } = req.body;

    if (!amount || amount < 0.50) {
      return res.status(400).json({
        error: 'Invalid amount. Minimum amount is $0.50'
      });
    }

    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(amount * 100), // Convert to cents
      currency,
      metadata,
      automatic_payment_methods: {
        enabled: true,
      },
    });

    res.json({
      clientSecret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id
    });
  } catch (error) {
    console.error('Payment intent creation failed:', error);
    res.status(500).json({
      error: 'Failed to create payment intent',
      message: error.message
    });
  }
});

// Create subscription
app.post('/api/create-subscription', async (req, res) => {
  try {
    const { customerId, priceId, paymentMethodId } = req.body;

    if (!customerId || !priceId) {
      return res.status(400).json({
        error: 'Customer ID and Price ID are required'
      });
    }

    // Attach payment method to customer if provided
    if (paymentMethodId) {
      await stripe.paymentMethods.attach(paymentMethodId, {
        customer: customerId,
      });

      await stripe.customers.update(customerId, {
        invoice_settings: {
          default_payment_method: paymentMethodId,
        },
      });
    }

    const subscription = await stripe.subscriptions.create({
      customer: customerId,
      items: [{ price: priceId }],
      payment_behavior: 'default_incomplete',
      expand: ['latest_invoice.payment_intent'],
    });

    res.json({
      subscriptionId: subscription.id,
      clientSecret: subscription.latest_invoice.payment_intent.client_secret,
    });
  } catch (error) {
    console.error('Subscription creation failed:', error);
    res.status(500).json({
      error: 'Failed to create subscription',
      message: error.message
    });
  }
});

// Create customer
app.post('/api/create-customer', async (req, res) => {
  try {
    console.log('Create customer request from origin:', req.headers.origin);
    const { email, name, metadata = {} } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const customer = await stripe.customers.create({
      email,
      name,
      metadata,
    });

    res.json({
      customerId: customer.id,
      email: customer.email,
      name: customer.name
    });
  } catch (error) {
    console.error('Customer creation failed:', error);
    res.status(500).json({
      error: 'Failed to create customer',
      message: error.message
    });
  }
});

// Get customer by email
app.get('/api/customer/:email', async (req, res) => {
  try {
    console.log('Get customer request from origin:', req.headers.origin);
    const { email } = req.params;

    const customers = await stripe.customers.list({
      email: email,
      limit: 1,
    });

    if (customers.data.length === 0) {
      return res.status(404).json({ error: 'Customer not found' });
    }

    const customer = customers.data[0];
    res.json({
      customerId: customer.id,
      email: customer.email,
      name: customer.name,
      created: customer.created
    });
  } catch (error) {
    console.error('Customer retrieval failed:', error);
    res.status(500).json({
      error: 'Failed to retrieve customer',
      message: error.message
    });
  }
});

// Cancel subscription
app.post('/api/cancel-subscription', async (req, res) => {
  try {
    const { subscriptionId } = req.body;

    if (!subscriptionId) {
      return res.status(400).json({ error: 'Subscription ID is required' });
    }

    const subscription = await stripe.subscriptions.update(subscriptionId, {
      cancel_at_period_end: true,
    });

    res.json({
      subscriptionId: subscription.id,
      cancelAtPeriodEnd: subscription.cancel_at_period_end,
      currentPeriodEnd: subscription.current_period_end
    });
  } catch (error) {
    console.error('Subscription cancellation failed:', error);
    res.status(500).json({
      error: 'Failed to cancel subscription',
      message: error.message
    });
  }
});

// Stripe webhook handler
app.post('/api/webhooks/stripe', (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle the event
  switch (event.type) {
    case 'payment_intent.succeeded':
      console.log('Payment succeeded:', event.data.object.id);
      // Add your business logic here
      break;

    case 'payment_intent.payment_failed':
      console.log('Payment failed:', event.data.object.id);
      // Add your business logic here
      break;

    case 'customer.subscription.created':
      console.log('Subscription created:', event.data.object.id);
      // Add your business logic here
      break;

    case 'customer.subscription.updated':
      console.log('Subscription updated:', event.data.object.id);
      // Add your business logic here
      break;

    case 'customer.subscription.deleted':
      console.log('Subscription deleted:', event.data.object.id);
      // Add your business logic here
      break;

    case 'invoice.payment_succeeded':
      console.log('Invoice payment succeeded:', event.data.object.id);
      // Add your business logic here
      break;

    case 'invoice.payment_failed':
      console.log('Invoice payment failed:', event.data.object.id);
      // Add your business logic here
      break;

    default:
      console.log(`Unhandled event type ${event.type}`);
  }

  res.json({ received: true });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log('CORS enabled for origins:', [
    'http://localhost:3000',
    'http://localhost:8080',
    'https://vibebeads.net', 
    'https://www.vibebeads.net'
  ]);
});
