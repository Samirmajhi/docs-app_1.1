const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');

// --- MongoDB Connection ---
const MONGO_URI = "mongodb+srv://samirkmajhi369:iRMUBAspLEEpsCvC@cluster0.tod3bfj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB Atlas!'))
  .catch(err => console.error('Could not connect to MongoDB:', err));

// --- Mongoose Models ---
const itemSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  inStock: { type: Boolean, required: true, default: true },
  category: { type: String },
}, { timestamps: true });
const Item = mongoose.model('Item', itemSchema);

const purchasedItemSchema = new mongoose.Schema({
  item: { type: mongoose.Schema.Types.ObjectId, ref: 'Item', required: true },
  totalPrice: { type: Number, required: true },
  purchaseDate: { type: Date, default: Date.now },
  paymentMethod: { type: String, enum: ['esewa', 'khalti'], required: true },
  status: { type: String, enum: ['pending', 'completed', 'refunded'], default: 'pending' },
}, { timestamps: true });
const PurchasedItem = mongoose.model('PurchasedItem', purchasedItemSchema);

const paymentSchema = new mongoose.Schema({
  transactionId: { type: String, unique: true },
  pidx: { type: String, unique: true },
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'PurchasedItem', required: true },
  amount: { type: Number, required: true },
  dataFromVerificationReq: { type: Object },
  apiQueryFromUser: { type: Object },
  paymentGateway: { type: String, enum: ['khalti', 'esewa', 'connectIps'], required: true },
  status: { type: String, enum: ['success', 'pending', 'failed'], default: 'pending' },
  paymentDate: { type: Date, default: Date.now },
}, { timestamps: true });
const Payment = mongoose.model('payment', paymentSchema);

// --- eSewa Integration Logic ---
const ESEWA_SECRET_KEY = "8gBm/:&EnhH.1/q";
const ESEWA_GATEWAY_URL = "https://rc-epay.esewa.com.np";
const ESEWA_PRODUCT_CODE = "EPAYTEST";

async function getEsewaPaymentHash({ amount, transaction_uuid }) {
  const data = `total_amount=${amount},transaction_uuid=${transaction_uuid},product_code=${ESEWA_PRODUCT_CODE}`;
  const hash = crypto.createHmac("sha256", ESEWA_SECRET_KEY).update(data).digest("base64");
  return {
    signature: hash,
    signed_field_names: "total_amount,transaction_uuid,product_code",
  };
}

async function verifyEsewaPayment(encodedData) {
  let decodedData = Buffer.from(encodedData, 'base64').toString('utf-8');
  decodedData = JSON.parse(decodedData);
  let headersList = {
    Accept: "application/json",
    "Content-Type": "application/json",
  };
  const data = `transaction_code=${decodedData.transaction_code},status=${decodedData.status},total_amount=${decodedData.total_amount},transaction_uuid=${decodedData.transaction_uuid},product_code=${ESEWA_PRODUCT_CODE},signed_field_names=${decodedData.signed_field_names}`;
  const hash = crypto.createHmac("sha256", ESEWA_SECRET_KEY).update(data).digest("base64");
  if (hash !== decodedData.signature) {
    throw { message: "Invalid Info: Signature mismatch", decodedData };
  }
  let reqOptions = {
    url: `${ESEWA_GATEWAY_URL}/api/epay/transaction/status/?product_code=${ESEWA_PRODUCT_CODE}&total_amount=${decodedData.total_amount}&transaction_uuid=${decodedData.transaction_uuid}`,
    method: "GET",
    headers: headersList,
  };
  let response = await axios.request(reqOptions);
  if (
    response.data.status !== "COMPLETE" ||
    response.data.transaction_uuid !== decodedData.transaction_uuid ||
    Number(response.data.total_amount) !== Number(decodedData.total_amount)
  ) {
    throw { message: "Invalid Info: Transaction verification failed", decodedData };
  }
  return { response: response.data, decodedData };
}

// --- Express App & Routes ---
const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// Ensure the three plans exist in the DB and return them
async function ensurePlans() {
  const plans = [
    { name: 'Free', price: 0, inStock: true, category: 'subscription' },
    { name: 'Base', price: 500, inStock: true, category: 'subscription' },
    { name: 'Pro', price: 1000, inStock: true, category: 'subscription' }
  ];
  const planDocs = [];
  for (const plan of plans) {
    let doc = await Item.findOne({ name: plan.name, price: plan.price });
    if (!doc) {
      doc = await Item.create(plan);
    }
    planDocs.push(doc);
  }
  return planDocs;
}

// Endpoint to fetch all plans
app.get('/plans', async (req, res) => {
  try {
    const plans = await ensurePlans();
    res.json({ success: true, plans });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Serve the frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Initialize eSewa payment
app.post('/initialize-esewa', async (req, res) => {
  try {
    const { itemId, totalPrice } = req.body;
    const itemData = await Item.findOne({ _id: itemId, price: Number(totalPrice) });
    if (!itemData) {
      return res.status(400).send({ success: false, message: "Item not found or price mismatch." });
    }
    const purchasedItemData = await PurchasedItem.create({
      item: itemId,
      paymentMethod: "esewa",
      totalPrice: totalPrice,
    });
    const paymentInitiate = await getEsewaPaymentHash({
      amount: totalPrice,
      transaction_uuid: purchasedItemData._id,
    });
    res.json({
      success: true,
      payment: paymentInitiate,
      purchasedItemData,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Verify eSewa payment
app.get('/complete-payment', async (req, res) => {
  const { data } = req.query;
  try {
    const paymentInfo = await verifyEsewaPayment(data);
    const purchasedItemData = await PurchasedItem.findById(paymentInfo.response.transaction_uuid);
    if (!purchasedItemData) {
      return res.status(500).json({ success: false, message: "Purchase not found" });
    }
    const paymentData = await Payment.create({
      pidx: paymentInfo.decodedData.transaction_code,
      transactionId: paymentInfo.decodedData.transaction_code,
      productId: paymentInfo.response.transaction_uuid,
      amount: purchasedItemData.totalPrice,
      dataFromVerificationReq: paymentInfo,
      apiQueryFromUser: req.query,
      paymentGateway: "esewa",
      status: "success",
    });
    await PurchasedItem.findByIdAndUpdate(paymentInfo.response.transaction_uuid, { $set: { status: "completed" } });
    res.json({ success: true, message: "Payment successful", paymentData });
  } catch (error) {
    res.status(500).json({ success: false, message: "An error occurred during payment verification", error: error.message });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
}); 