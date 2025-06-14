app.get('/cart', (req, res) => {
  const cart = req.session.cart || [];

  // Calculate subtotal
  const subtotal = cart.reduce((sum, item) => sum + item.price * item.qty, 0);
  const shipping = 2000; // Flat shipping rate (you can change this)
  const total = subtotal + shipping;

  res.render('cart', { cart, subtotal, shipping, total });
});


app.post('/add-to-cart', async (req, res) => {
  const productId = req.body.product_id;

  // Fetch product details from DB (you can also pass all via hidden fields if you prefer)
  const result = await pool.query('SELECT * FROM products WHERE id = $1', [productId]);
  const product = result.rows[0];

  if (!product) return res.redirect('back');

  // Initialize cart if it doesn't exist
  if (!req.session.cart) {
    req.session.cart = [];
  }

  // Check if product already exists in cart
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

  res.redirect('/cart');
});


app.post('/cart/increase/:id', (req, res) => {
  const cart = req.session.cart || [];
  const product = cart.find(p => p.id == req.params.id);
  if (product) product.qty += 1;
  res.redirect('/cart');
});

app.post('/cart/decrease/:id', (req, res) => {
  const cart = req.session.cart || [];
  const product = cart.find(p => p.id == req.params.id);
  if (product && product.qty > 1) product.qty -= 1;
  res.redirect('/cart');
});

app.post('/cart/remove/:id', (req, res) => {
  req.session.cart = (req.session.cart || []).filter(p => p.id != req.params.id);
  res.redirect('/cart');
});

app.post('/cart/clear', (req, res) => {
  req.session.cart = [];
  res.redirect('/cart');
});
