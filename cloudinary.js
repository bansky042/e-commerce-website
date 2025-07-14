// config/cloudinary.js
require('dotenv').config(); // ← Add this at the top
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
// Ensure you have installed the required packages:
// Configure your Cloudinary credentials
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Multer Storage using Cloudinary
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'ecommerce-products', // Optional folder in Cloudinary
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp']
  }
});

const upload = require('multer')({ storage });

module.exports = {
  cloudinary,
  upload
};
