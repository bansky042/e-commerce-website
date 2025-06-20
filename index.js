const express = require("express");
const { Pool } = require("pg");
const multer = require("multer");
const path = require("path");
const bcrypt = require("bcryptjs");
const passport = require("passport");
const { Strategy } = require("passport-local");
const session = require("express-session");
const cookieParser = require('cookie-parser');
const Stripe = require('stripe');
const cors = require('cors');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const { userInfo } = require("os");
dotenv.config();

const app = express();
const port = 3000;
const saltRounds = 10;

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// Middleware
app.use(cors());
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true })); // For form handling
app.set("view engine", "ejs");
app.use(cookieParser());
app.use("/uploads", express.static("uploads"));
app.use(express.static(path.join(__dirname, "public"))); // Serve static files from public directory
app.use(express.json());


app.use(session({
  secret: "TOPWORLLDSECRET",
  resave: false,
  saveUninitialized: false,
  
  cookie: { maxAge: 1000 * 60 * 60 * 24 },
}));

app.use(passport.initialize());
app.use(passport.session());

// PostgreSQL Pool
const pool = new Pool({
  user: process.env.POSTGRES_USER || "postgres",
  host: process.env.POSTGRES_HOST || "localhost",
  database: process.env.POSTGRES_DB || "e-commerce",
  password: process.env.POSTGRES_PASSWORD || "bansky@100",
  port: process.env.POSTGRES_PORT || 5432,
});

// Multer Setup (for local file upload)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "public/uploads"),
  filename: (req, file, cb) =>
    cb(null, Date.now() + path.extname(file.originalname)),
});


const upload = multer({ storage });

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: "abanakosisochukwu03@gmail.com",
    pass: "lkwe ehad ybwd kcbg",
  },
});

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  console.log("Saving return URL:", req.originalUrl);
  req.session.returnTo = req.originalUrl;
  res.redirect("/login");
}



function isadmin(req, res, next) {
  if (req.isAuthenticated() && req.user.is_admin === true) {
    return next();
  }
  res.redirect('/login');
}

function emailVerified(req, res, next) {
  if (req.isAuthenticated() && req.user.email_verified === true) {
    return next();
  }
  res.redirect('/login');
}

// Routes
app.get("/", async (req, res) => {
  
  try {
    const result = await pool.query("SELECT * FROM products ORDER BY created_at DESC");
    const user = await pool.query("SELECT * FROM users WHERE id = $1", [req.session.passport.user]);
    const userData = user.rows[0];
    console.log(userData);
    res.render("index.ejs", { products: result.rows, user: userData });
  } catch (err) {
    console.error("Error fetching products:", err);
    res.render("index.ejs", { products: [] });
  }
});
app.get("/login", (req, res) => res.render("login.ejs"));
app.get("/forgottenpassword", (req, res) => res.render("forgottenPassword.ejs"));
app.get("/forgotpassword", (req, res) => res.render("forgotpassword.ejs"));
app.get("/verify-otp", (req, res) => res.render("otp.ejs"));
app.get('/register', async (req, res) => res.render("register.ejs"));

app.get('/admin', isadmin, (req, res) => {
  res.render('admin-home', {users: req.user}); // or whatever you named it
});


app.get('/admin/dashboard', isadmin, async (req, res) => {
  const result = await pool.query("SELECT * FROM users");
const users = result.rows; // ✅ This must be an array

  try {
    const totalUsersResult = await pool.query(`SELECT COUNT(*) FROM users`);
    const totalUsers = parseInt(totalUsersResult.rows[0].count, 10);

    const totalRevenueResult = await pool.query(`SELECT COALESCE(SUM(price), 0) AS total FROM order_history`);
    const totalRevenue = parseFloat(totalRevenueResult.rows[0].total);

    const monthlySalesResult = await pool.query(`
      SELECT EXTRACT(MONTH FROM purchased_at) AS month, SUM(price) AS total
      FROM order_history
      GROUP BY month ORDER BY month
    `);

    const salesByMonth = Array(12).fill(0);
    monthlySalesResult.rows.forEach(row => {
      salesByMonth[parseInt(row.month, 10) - 1] = parseFloat(row.total);
    });

    res.render('admin-dashboard', {
      totalUsers,
      totalRevenue,
      salesByMonth,
      users, // Pass the user data to the view
    });
  } catch (err) {
    console.error("Admin dashboard error:", err.message);
    res.status(500).send("Server error");
  }
});




// Handle product upload
app.post("/admin/products", isadmin, upload.single("image"), async (req, res) => {
  const {
    first_category,
    second_category,
    name,
    price,
    short_description,
    description,
    key_features,
    specifications,
    in_the_box,
    stock
  } = req.body;

  const image_url = `/uploads/${req.file.filename}`;

  // Convert comma-separated strings to arrays, trimming whitespace
  const keyFeaturesArray = key_features
    ? key_features.split(",").map(f => f.trim())
    : [];

  const specificationsArray = specifications
    ? specifications.split(",").map(s => s.trim())
    : [];

  const inTheBoxArray = in_the_box
    ? in_the_box.split(",").map(i => i.trim())
    : [];

  try {
    await pool.query(
      `INSERT INTO products (
        first_category,
        second_category,
        name,
        image_url,
        price,
        short_description,
        description,
        key_features,
        specifications,
        in_the_box,
        stock
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [
        first_category,
        second_category,
        name,
        image_url,
        price,
        short_description,
        description,
        keyFeaturesArray,
        specificationsArray,
        inTheBoxArray,
        stock
      ]
    );
    console.log("Product inserted successfully:", {
      first_category,
      second_category,
      name,
      price,
      short_description,
      description,
      keyFeaturesArray,
      specificationsArray,
      inTheBoxArray,
      stock
    });
    console.log("Image URL:", image_url);
    res.redirect("/");
  } catch (err) {
    console.error("Error inserting product:", err);
    res.status(500).send("Failed to add product.");
  }
});




// Route to block/unblock user
app.post("/admin/dashboard/:id/block", isadmin, async (req, res) => {
  const userId = req.params.id;
  try {
    const user = await pool.query("SELECT email_verified FROM users WHERE id = $1", [userId]);
    if (user.rows.length === 0) return res.status(404).send("User not found");

    const newStatus = !user.rows[0].is_blocked;
    await pool.query("UPDATE users SET email_verified = $1 WHERE id = $2", [newStatus, userId]);
    res.redirect("/admin/dashboard");
  } catch (err) {
    console.error("Error updating user block status:", err);
    res.status(500).send("Server error");
  }
});



app.post("/admin/dashboard/:id/toggle", isadmin, async (req, res) => {
  const userId = req.params.id;

  try {
    // Get current block status
    const result = await pool.query("SELECT email_verified FROM users WHERE id = $1", [userId]);

    if (result.rows.length === 0) return res.status(404).send("User not found");

    const isBlocked = result.rows[0].email_verified;

    // Toggle status
    await pool.query("UPDATE users SET email_verified = $1 WHERE id = $2", [!isBlocked, userId]);

    res.redirect("/admin/dashboard"); // or send JSON: res.json({ success: true })
  } catch (err) {
    console.error("Error toggling user block status:", err.message);
    res.status(500).send("Server error");
  }
});





// Route to view individual user's orders
app.get('/admin/users/:id', isadmin, async (req, res) => {
  const userId = req.params.id;

  try {
    const userQuery = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    const user = userQuery.rows[0];

    const ordersQuery = await pool.query(`
      SELECT oh.id, oh.tx_ref AS track_number, oh.purchased_at, oh.estimated_delivery
      FROM order_history oh
      JOIN products p ON oh.product_id = p.id
      WHERE oh.user_id = $1
      ORDER BY oh.purchased_at DESC
    `, [userId]);



console.log('Orders query result:', ordersQuery.rows);


    res.render('admin-user-orders', {
      user,
      userId,
      orders: ordersQuery.rows,
    });
  } catch (err) {
    console.error('Error fetching user orders:', err.message);
    res.status(500).send('Server error');
  }
});


// Route to update estimated delivery date


app.post('/admin/users/:userId/orders/:orderId/update', isadmin, async (req, res) => {
  const userId = parseInt(req.params.userId);
  const orderId = parseInt(req.params.orderId);
  const { estimated_delivery } = req.body;

  if (isNaN(userId) || isNaN(orderId)) {
    return res.status(400).send("Invalid IDs");
  }

  try {
    await pool.query(
      'UPDATE order_history SET estimated_delivery = $1 WHERE id = $2 AND user_id = $3',
      [estimated_delivery, orderId, userId]
    );
    res.redirect(`/admin/users/${userId}`);
  } catch (err) {
    console.error("Error updating estimated delivery:", err.message);
    res.status(500).send("Server error");
  }
});












app.get('/categories', isLoggedIn, emailVerified, async (req, res) => {
  if(!req.isAuthenticated()) {
    return res.redirect('/login');
  }
  try {
    const result = await pool.query(`
      SELECT DISTINCT first_category AS name FROM products
    `);
    const categories = result.rows;
    res.render('categories', { categories, user:req.user });
  } catch (err) {
    console.error('Error fetching categories:', err);
    res.status(500).send('Server error');
  }
});

app.get('/category/:mainCategory', isLoggedIn, emailVerified, async (req, res) => {
  if(!req.isAuthenticated()) {
    return res.redirect('/login');
  }
  const mainCategory = decodeURIComponent(req.params.mainCategory);
  try {
    const result = await pool.query(
      `SELECT DISTINCT TRIM(second_category) AS second_category FROM products WHERE TRIM(first_category) = $1`,
      [mainCategory.trim()]
    );
    
    const subcategories = result.rows;
    res.render('category', { mainCategory, subcategories, user:req.user });
  } catch (err) {
    console.error('Error fetching subcategories:', err);
    res.status(500).send('Server error');
  }
});




  

app.get('/products/:mainCategory/:subCategory', isLoggedIn,emailVerified, async (req, res) => {
  if(!req.isAuthenticated()) {
    return res.redirect('/login');
  }
  const mainCategory = decodeURIComponent(req.params.mainCategory);
  const subCategory = decodeURIComponent(req.params.subCategory);

  try {
    const result = await pool.query(
      `SELECT * FROM products WHERE first_category = $1 AND second_category = $2`,
      [mainCategory, subCategory]
    );
    const products = result.rows;
    res.render('subcategory-products', { mainCategory, subCategory, products });
  } catch (err) {
    console.error('Error fetching products:', err);
    res.status(500).send('Server error');
  }
});

app.get("/product/:id",isLoggedIn,emailVerified, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await pool.query("SELECT * FROM products WHERE id = $1", [id]);
    const product = rows[0];


   
    res.render("product", { product,
      user:req.user
     });
  } catch (err) {
    console.error("Error fetching product:", err);
    res.redirect("/");
  }
});


app.get('/account', isLoggedIn, emailVerified, async (req, res) => {
  const userId = req.user.id;

  try {
    // Fetch user data
    const userQuery = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    const user = userQuery.rows[0];

    // Get total number of orders by user
    const totalOrdersResult = await pool.query(`
      SELECT COUNT(DISTINCT purchased_at) AS total_orders
      FROM order_history
      WHERE user_id = $1
    `, [userId]);

    const totalOrders = totalOrdersResult.rows[0].total_orders;

    // Get recent 3 products ordered by user
    const recentOrders = await pool.query(`
      SELECT oh.product_id, p.name, p.image_url, oh.purchased_at
      FROM order_history oh
      JOIN products p ON oh.product_id = p.id
      WHERE oh.user_id = $1
      ORDER BY oh.purchased_at DESC
      LIMIT 3
    `, [userId]);

   
    // Render EJS view with all data
    res.render('account', {
      user,
      totalOrders,
      recentProducts: recentOrders.rows,
     
    });

  } catch (err) {
    console.error('Error loading account page:', err.message);
    res.status(500).send('Server error');
  }
});



// PATCH route to update address and phone number
app.patch('/update-address', async (req, res) => {
  const { address, phone_number } = req.body;
  const userId = req.user.id; // adjust if you use different session setup

  if (!userId) return res.status(401).json({ message: "Unauthorized" });

  try {
    await pool.query(
      'UPDATE users SET address = $1, phone_number = $2 WHERE id = $3',
      [address, phone_number, userId]
    );
    console.log('Address updated for user:', userId);
    res.status(200).json({ message: 'Address updated' });
  } catch (error) {
    console.error('Update error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});



app.get("/cont", (req, res) => { 
  res.render("cont.ejs");
});


app.get("/search",isLoggedIn,emailVerified, async (req, res) => {
  const query = req.query.q?.trim().toLowerCase() || "";

  if (!query) {
    return res.render("search", { products: [], query: "" });
  }

  try {
    const result = await pool.query(
      `SELECT * FROM products WHERE LOWER(name) LIKE $1`,
      [`%${query}%`]
    );
    res.render("search", { products: result.rows, query, user:req.user });
  } catch (error) {
    console.error("Search error:", error);
    res.render("search", { products: [], query });
  }
});



// In your routes/index.js or a separate history.js file

app.get('/history', isLoggedIn, emailVerified, async (req, res) => {
  try {
    const userId = req.user.id;
    const start = req.query.start || '';
    const end = req.query.end || '';

    let query = `
      SELECT 
        oh.product_id,
        p.name AS product_name,
        p.image_url,
        oh.quantity,
        oh.tx_ref,
        p.price AS product_price,
        oh.purchased_at
      FROM order_history oh
      JOIN products p ON oh.product_id = p.id
      WHERE oh.user_id = $1
    `;
    
    const params = [userId];
    console.log('User ID:', userId);

    if (start && end) {
      query += ` AND oh.purchased_at BETWEEN $2 AND $3`;
      params.push(start, end);
    }

    query += ` ORDER BY oh.purchased_at DESC`;

    const { rows: orders } = await pool.query(query, params);

    res.render('history', {
      user: req.user || null,
      orders,
      start,
      end
    });

  } catch (err) {
    console.error('Error fetching order history:', err);
    res.render('history', {
      user: req.user || null,
      orders: [],
      start: '',
      end: ''
    });
  }
});

// GET route for tracking order
app.get('/track-order/:tx_ref', isLoggedIn, emailVerified, async (req, res) => {
  const { tx_ref } = req.params;
  const user = req.user;
  if (!user) {
    return res.status(401).send('Unauthorized. Please log in.');
  }

  try {
    const result = await pool.query(
      `SELECT oh.*, p.name AS product_name, p.image_url 
       FROM order_history oh
       JOIN products p ON oh.product_id = p.id
       WHERE oh.tx_ref = $1`,
      [tx_ref]
    );
    console.log('Tracking order for tx_ref:', tx_ref);
    console.log('Query result:', result.rows);
    if (result.rows.length === 0) {
      return res.status(404).send('Order not found.');
    }

    const orders = result.rows;

    // Calculate total price of all items under the same tx_ref
    const totalPrice = orders.reduce((sum, order) => sum + (parseFloat(order.price) || 0), 0);

    // Estimate arrival date (5 days after first purchase)
    const estimatedArrival = new Date(orders[0].purchased_at);
    estimatedArrival.setDate(estimatedArrival.getDate() + 5);

    res.render('track-order', {
      orders,
      totalPrice,
      estimatedArrival,
      tx_ref,
      user
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error.');
  }
});






app.get('/cart',isLoggedIn, emailVerified, async (req, res) => {
  if(!req.isAuthenticated()) {
    return res.redirect('/login');
  }
  try {
    const userId = req.user.id; // Ensure user is logged in

    // Fetch all cart items for the user
    const dbCheck = await pool.query(`
      SELECT c.*, p.name, p.image_url
      FROM cart c
      JOIN products p ON c.product_id = p.id
      WHERE c.user_id = $1
    `, [userId]);

    const result = dbCheck.rows;
console.log(result);
    if (result.length === 0) {
      return res.render('cart', { result: [], subtotal: 0, shipping: 0, total: 0, user:req.user });
    }
    // Calculate subtotal
    const subtotal = result.reduce((sum, item) => sum + item.product_price * item.quantity, 0);
    const shipping = 2000; // Flat shipping rate
    const total = subtotal + shipping;

    res.render('cart', { result, subtotal, shipping, total, user:req.user });

  } catch (err) {
    console.error('Error fetching cart:', err);
    res.status(500).send('Server error loading cart');
  }
});


app.post('/add-to-cart', async (req, res) => {
  
  const productId = req.body.product_id;
  const userId = req.user.id; // Ensure user is logged in

  const result = await pool.query('SELECT * FROM products WHERE id = $1', [productId]);
  const product = result.rows[0];

  if (!product) return res.redirect('back');

  // Initialize session cart
  if (!req.session.cart) req.session.cart = [];

  // Check session cart
  const existing = req.session.cart.find(p => p.id === product.id);
  if (existing) {
    existing.qty += 1;
  } else {
    req.session.cart.push({
      id: product.id,
      name: product.name,
      price: product.price,
      image_url: product.image_url,
      qty: 1
    });
  }

  // Check if item already exists in DB cart
  const dbCheck = await pool.query(`
    SELECT * FROM cart WHERE user_id = $1 AND product_id = $2
  `, [userId, productId]);

  if (dbCheck.rows.length > 0) {
    // If exists, update quantity
    await pool.query(`
      UPDATE cart SET quantity = quantity + 1 WHERE user_id = $1 AND product_id = $2
    `, [userId, productId]);
  } else {
    // If not, insert new row
    await pool.query(`
      INSERT INTO cart (user_id, product_id, product_name, product_price, image_url, quantity)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [userId, product.id, product.name, product.price, product.image_url, 1]);
  }

  res.redirect('/cart');
});



app.post('/cart/increase/:id', async (req, res) => {
  const userId = req.user.id;
  const productId = req.params.id;

  await pool.query(`
    UPDATE cart 
    SET quantity = quantity + 1 
    WHERE user_id = $1 AND product_id = $2
  `, [userId, productId]);

  res.redirect('/cart');
});


app.post('/cart/decrease/:id', async (req, res) => {
  const userId = req.user.id;
  const productId = req.params.id;

  // Only decrease if qty > 1
  await pool.query(`
    UPDATE cart 
    SET quantity = GREATEST(quantity - 1, 1)
    WHERE user_id = $1 AND product_id = $2
  `, [userId, productId]);

  res.redirect('/cart');
});


app.post('/cart/remove/:id', async (req, res) => {
  const userId = req.user.id;
  const productId = req.params.id;

  await pool.query(`
    DELETE FROM cart 
    WHERE user_id = $1 AND product_id = $2
  `, [userId, productId]);

  res.redirect('/cart');
});


app.post('/cart/clear', async (req, res) => {
  const userId = req.user.id;

  await pool.query(`
    DELETE FROM cart 
    WHERE user_id = $1
  `, [userId]);

  res.redirect('/cart');
});



// Admin product upload page
app.get("/admin/products", (req, res) => {

  res.render("admin-add-product.ejs");
});




app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/login");
  });
});

app.post("/login", passport.authenticate("local", {
  failureRedirect: "/login",
  failureFlash: true
}), (req, res) => {
  console.log("Session content after login:", req.session);
  const redirectTo = req.session.returnTo || "/";
  console.log("Redirecting to:", redirectTo);
  delete req.session.returnTo;
  res.redirect(redirectTo);
});











// GET /payment - Show flutterwave payment or manual form
app.get('/payment/:amount',isLoggedIn, emailVerified, (req, res) => {
  
  const rawAmount = req.params.amount;
  const amount = parseFloat(rawAmount);

  if (isNaN(amount) || amount <= 0) {
    return res.redirect('/cart');
  }

  const flutterwaveConfig = {
    public_key: 'FLWPUBK_TEST-639a874a89faeee1bad25670aaaccdf9-X',
    tx_ref: `TX-${Date.now()}`,
    amount: amount,
    currency: 'NGN',
    payment_options: 'card,banktransfer,ussd',
    customer: {
      email: req.user.email || 'test@example.com',
      phone_number: req.user.phone || '08100000000',
      name: req.user.name || 'John Doe',
    },
    customizations: {
      title: 'BanMarket Checkout',
      description: `Payment for items worth ₦${amount}`,
      logo: 'https://st2.depositphotos.com/4403291/7418/v/450/depositphotos_74189661-stock-illustration-online-shop-log.jpg',
    }
  };

  res.render('payment', { flutterwaveConfig });
});

app.post('/payment-success', async (req, res) => {
  const { tx_ref } = req.body;
  const userId = req.user.id;

  try {
    const timestamp = new Date();

    const cartItems = await pool.query(
      `SELECT * FROM cart WHERE user_id = $1`,
      [userId]
    );

    for (const item of cartItems.rows) {
      const productResult = await pool.query(
        `SELECT price FROM products WHERE id = $1`,
        [item.product_id]
      );
      const price = productResult.rows[0]?.price;

      await pool.query(
        `INSERT INTO order_history (user_id, product_id, quantity, price, purchased_at, tx_ref)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [item.user_id, item.product_id, item.quantity, price, timestamp, tx_ref]
      );
    }

    await pool.query(`DELETE FROM cart WHERE user_id = $1`, [userId]);

    res.json({ success: true });

  } catch (err) {
    console.error('Error saving order after payment:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});




app.get('/checkout', async (req, res) => {
  const userId = req.session.userId;
  const result = await pool.query('SELECT SUM(product_price * quantity) AS total FROM cart WHERE user_id = $1', [userId]);
  const total = result.rows[0].total || 0;
  res.redirect(`/payment?amount=${total}`);
});


app.get('/success', (req, res) => {
 res.render('success.ejs')
});

app.post('/create-payment-intent', async (req, res) => {
  const { amount } = req.body;
  const userId = req.user.id;

  try {
    // 1. Create a new Stripe payment intent
    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency: 'NGN',
      payment_method_types: ['card'],
    });

    // 2. Get all cart items for the user
    const cartItems = await pool.query(
      `SELECT * FROM cart WHERE user_id = $1`,
      [userId]
    );

    const timestamp = new Date();

    // 3. Insert each cart item into order_history
    for (const item of cartItems.rows) {
      // Get product price
      const productResult = await pool.query(
        `SELECT price FROM products WHERE id = $1`, [item.product_id]
      );
      const price = productResult.rows[0]?.price;
    
      await pool.query(
        `INSERT INTO order_history (user_id, product_id, quantity, price, purchased_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [item.user_id, item.product_id, item.quantity, price, timestamp]
      );
    }
    

    // 4. Delete the cart items
    await pool.query(`DELETE FROM cart WHERE user_id = $1`, [userId]);

    // 5. Respond with client secret
    res.json({ clientSecret: paymentIntent.client_secret });

  } catch (err) {
    console.error('Error processing payment intent:', err.message);
    res.status(500).json({ error: err.message });
  }
});



app.post("/forgottenpassword", async (req, res) => {
  const { username: email, phoneNumber } = req.body;

  if (!email || !phoneNumber) {
    return res.status(400).send("Email and phone number are required.");
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  await pool.query("INSERT INTO otps (email, otp) VALUES ($1, $2)", [email, otp]); // Store OTP in database
  console.log(`Stored OTP for ${email}: ${otp}`); // Debugging
  console.log(`OTP stored in database for ${email}`); // Additional debugging

  // Send OTP via email
  
  const mailOptions = {
    from: "abanakosisochukwu03@gmail.com",
    to: email,
    subject: 'Your OTP Code',
    text: `Your OTP code is ${otp}`,
  };

  transporter.sendMail(mailOptions, (error) => {
    if (error) return res.status(500).send('Error sending OTP');

    res.render("otp.ejs", { email: email }); // Make sure email is passed to OTP page
  });
});

app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    console.log("Missing email or OTP in request body:", req.body);
    return res.status(400).send("Email and OTP are required.");
  }

  console.log(`Submitted OTP: ${otp}`);

  const result = await pool.query("SELECT * FROM otps WHERE email = $1 AND otp = $2", [email, otp]);
  console.log(`Query result for ${email}:`, result.rows); // Additional logging for debugging
  if (result.rows.length > 0) {
    res.render("forgotpassword.ejs"); // Render the forgotpassword page
    console.log(`Redirecting to forgotpassword page for ${email}`); // Additional debugging
    await pool.query("DELETE FROM otps WHERE email = $1 AND otp = $2", [email, otp]); // Clear OTP after successful verification
  } else {
    res.status(400).send('Invalid OTP');
  }
});

app.post("/forgotpassword", async (req, res, next) => {
  try {
    if (!req.body || !req.body.email || !req.body.newPassword) {
      return res.status(400).send("Email and new password are required.");
    }

    const email = req.body.email.trim().toLowerCase();
    const newPassword = req.body.newPassword;

    // Check if user exists
    const userCheck = await pool.query("SELECT * FROM users WHERE LOWER(email) = $1", [email]);

    if (userCheck.rows.length === 0) {
      return res.status(404).send("User not found");
    }

    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update password
    const result = await pool.query(
      "UPDATE users SET password = $1 WHERE email = $2 RETURNING *", 
      [hashedPassword, email]
    );

    if (result.rows.length === 0) {
      return res.status(404).send("User not found after update");
    }

    const updatedUser = result.rows[0];

    // Log in the user after password reset
    req.login(updatedUser, (err) => {
      if (err) {
        console.error("Error logging in user after password reset:", err);
        return next(err);
      }
      return res.redirect("/");
    });

  } catch (error) {
    console.error(error);
    res.status(500).send("Error updating password.");
  }
});



const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

app.post("/register", async (req, res) => {
  const {
    email,
    confirmPassword,
    phoneNumber,
    username,
    country,
    fullname,
    address,
    city,
    state,
    postal_code,
  } = req.body;

  const otp = generateOTP();
  const otpCreatedAt = new Date();

  try {
    // Check if email already exists
    const userExists = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userExists.rows.length > 0) {
      return res.send("Email already exists.");
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(confirmPassword, saltRounds);

    // Create user
    const result = await pool.query(
      `INSERT INTO users (
        full_name, username, email, password, phone_number, country,
        address, city, state, postal_code, otp_code, otp_created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING id, email`,
      [
        fullname,
        username,
        email,
        hashedPassword,
        phoneNumber,
        country,
        address,
        city,
        state,
        postal_code,
        otp,
        otpCreatedAt
      ]
    );

    const newUser = result.rows[0];
    req.session.tempUserId = newUser.id;

    // Send OTP via email
    const mailOptions = {
      from: "abanakosisochukwu03@gmail.com",
      to: email,
      subject: "OTP to complete your registration",
      html: `
        <h3>Hello,</h3>
        <p>Your OTP code is: <strong>${otp}</strong></p>
        <p>This code is valid for <strong>5 minutes</strong>.</p>
        <p>If you did not request this, please ignore this email.</p>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log("📨 OTP sent to", email, ":", otp);

    return res.render("verify-otp", { email, message: null });

  } catch (err) {
    console.error("❌ Error registering user:", err);
    return res.status(500).send("Failed to register.");
  }
});





app.get("/verify-otps", async (req, res) => {
  const userId = req.session.tempUserId;
  if (!userId) return res.redirect("/register");

  const result = await pool.query("SELECT email FROM users WHERE id = $1", [userId]);
  const user = result.rows[0];

  res.render("verify-otp", {
    email: user?.email || "",
    message: null
  });
});



app.post("/verify-otps", async (req, res) => {
  const { otp } = req.body;
  const userId = req.session.tempUserId;

  if (!userId) return res.redirect("/register");

  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [userId]);
    const user = result.rows[0];

    if (!user?.otp_code || !user.otp_created_at) {
      return res.render("verify-otp", {
        message: "OTP not found or expired.",
        email: user?.email || ""
      });
    }

    const now = new Date();
    const created = new Date(user.otp_created_at);
    const isExpired = (now - created) > 5 * 60 * 1000; // 5 mins
    const isMatch = otp.trim() === user.otp_code.trim();

    console.log("🔐 OTP:", otp, "| Stored:", user.otp_code, "| Expired?", isExpired);

    if (!isExpired && isMatch) {
      await pool.query(
        "UPDATE users SET email_verified = true, otp_code = null, otp_created_at = null WHERE id = $1",
        [userId]
      );

      req.login(user, (err) => {
        if (err) return res.redirect("/login");
        return res.redirect("/account");
      });

    } else {
      return res.render("verify-otp", {
        message: "Invalid or expired OTP.",
        email: user.email
      });
    }

  } catch (err) {
    console.error("❌ OTP verification error:", err);
    return res.status(500).send("Internal server error.");
  }
});








passport.use(new Strategy(async (username, password, cb) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [username]);
    if (result.rows.length === 0) return cb(null, false, { message: "User not found" });

    const user = result.rows[0];
    bcrypt.compare(password, user.password, (err, match) => {
      if (err) return cb(err);
      return match ? cb(null, user) : cb(null, false, { message: "Incorrect password" });
    });
  } catch (err) {
    return cb(err);
  }
}));

passport.serializeUser((user, cb) => {
  cb(null, user.id); // Store only the user ID
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    cb(null, result.rows[0]);
  } catch (err) {
    cb(err);
  }
});


// Start Server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
