require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');

const server = express();

// Database configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'KeyChingDB',
  waitForConnections: true,
  connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT) || 10,
  queueLimit: 0
};

// Create connection pool
const pool = mysql.createPool(dbConfig);

// Middleware
server.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));
server.use(express.json({ limit: '10mb' }));
server.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging middleware
server.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Health check endpoint
server.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Custom authentication route
server.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Username and password are required' 
      });
    }

    const [users] = await pool.execute(
      'SELECT * FROM userData WHERE username = ?',
      [username]
    );

    const user = users[0];

    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }

    // Check if user is banned
    if (user.isBanned) {
      return res.status(403).json({ 
        success: false, 
        message: 'Account is banned', 
        banReason: user.banReason 
      });
    }

    // Compare password with hash
    const isValidPassword = await bcrypt.compare(password, user.passwordHash);

    if (isValidPassword) {
      const userData = { ...user };
      delete userData.passwordHash; // Don't send password hash

      // Update last login with proper MySQL datetime format
      const currentDateTime = new Date().toISOString().slice(0, 19).replace('T', ' ');
      
      await pool.execute(
        'UPDATE userData SET loginStatus = true, lastLogin = ? WHERE username = ?',
        [currentDateTime, username]
      );

      // Generate a proper JWT-like token (in production, use actual JWT)
      const token = Buffer.from(`${user.id}_${Date.now()}_${Math.random()}`).toString('base64');

      res.json({
        success: true,
        user: userData,
        token: token,
        message: 'Login successful'
      });
    } else {
      res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error occurred during login' 
    });
  }
});

// Custom registration route
server.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, firstName, lastName, accountType, birthDate } = req.body;

    // Validate required fields
    if (!username || !email || !password || !firstName) {
      return res.status(400).json({ 
        success: false, 
        message: 'Username, email, password, and first name are required' 
      });
    }

    // Check if username already exists
    const [existingUsers] = await pool.execute(
      'SELECT id FROM userData WHERE username = ? OR email = ?',
      [username, email]
    );

    if (existingUsers.length > 0) {
      return res.status(409).json({ 
        success: false, 
        message: 'Username or email already exists' 
      });
    }

    // Hash the password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Helper function to convert ISO datetime to MySQL format
    const formatDateTimeForMySQL = (dateTime) => {
      if (!dateTime) return null;
      if (typeof dateTime === 'string') {
        return new Date(dateTime).toISOString().slice(0, 19).replace('T', ' ');
      }
      if (typeof dateTime === 'number') {
        return new Date(dateTime).toISOString().slice(0, 19).replace('T', ' ');
      }
      return null;
    };

    // Generate a unique ID (since the schema uses VARCHAR(10))
    const generateId = () => {
      return Math.random().toString(36).substring(2, 12).toUpperCase();
    };

    const userId = generateId();
    const currentTime = Date.now();
    const currentDateTime = formatDateTimeForMySQL(new Date());

    const newUser = {
      id: userId,
      loginStatus: true,
      lastLogin: currentDateTime,
      accountType: accountType || 'buyer',
      username: username,
      email: email,
      firstName: firstName,
      lastName: lastName || '',
      phoneNumber: '',
      birthDate: birthDate || null,
      encryptionKey: `enc_key_${Date.now()}`,
      credits: 100, // Starting credits
      reportCount: 0,
      isBanned: false,
      banReason: '',
      banDate: null,
      banDuration: null,
      createdAt: currentTime,
      updatedAt: currentTime,
      passwordHash: passwordHash,
      twoFactorEnabled: false,
      twoFactorSecret: '',
      recoveryCodes: [],
      profilePicture: `https://i.pravatar.cc/150?img=${Math.floor(Math.random() * 70) + 1}`,
      bio: '',
      socialLinks: {}
    };

    const [result] = await pool.execute(
      'INSERT INTO userData (id, loginStatus, lastLogin, accountType, username, email, firstName, lastName, phoneNumber, birthDate, encryptionKey, credits, reportCount, isBanned, banReason, banDate, banDuration, createdAt, updatedAt, passwordHash, twoFactorEnabled, twoFactorSecret, recoveryCodes, profilePicture, bio, socialLinks) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [
        newUser.id,
        newUser.loginStatus,
        newUser.lastLogin,
        newUser.accountType,
        newUser.username,
        newUser.email,
        newUser.firstName,
        newUser.lastName,
        newUser.phoneNumber,
        newUser.birthDate,
        newUser.encryptionKey,
        newUser.credits,
        newUser.reportCount,
        newUser.isBanned,
        newUser.banReason,
        formatDateTimeForMySQL(newUser.banDate),
        newUser.banDuration,
        newUser.createdAt,
        newUser.updatedAt,
        newUser.passwordHash,
        newUser.twoFactorEnabled,
        newUser.twoFactorSecret,
        JSON.stringify(newUser.recoveryCodes),
        newUser.profilePicture,
        newUser.bio,
        JSON.stringify(newUser.socialLinks)
      ]
    );

    // Generate token for automatic login
    const token = Buffer.from(`${userId}_${Date.now()}_${Math.random()}`).toString('base64');

    // Return user data without password hash
    const userData = { ...newUser };
    delete userData.passwordHash;

    res.status(201).json({
      success: true,
      user: userData,
      token: token,
      message: 'Account created successfully'
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error occurred during registration' 
    });
  }
});

// Custom logout route
server.post('/api/auth/logout', async (req, res) => {
  try {
    const { username } = req.body;

    if (username) {
      // Update login status in database
      await pool.execute(
        'UPDATE userData SET loginStatus = false WHERE username = ?',
        [username]
      );
    }

    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error occurred during logout' 
    });
  }
});

// Custom wallet balance route
server.get('/api/wallet/balance', async (req, res) => {
  try {
    const username = req.query.username || 'user_123'; // Default for demo

    const [wallets] = await pool.execute(
      'SELECT * FROM wallet WHERE username = ?',
      [username]
    );

    const [users] = await pool.execute(
      'SELECT credits FROM userData WHERE username = ?',
      [username]
    );

    const wallet = wallets[0];
    const user = users[0];

    if (wallet && user) {
      res.json({
        balance: wallet.balance,
        credits: user.credits,
        totalEarned: wallet.totalEarned,
        totalSpent: wallet.totalSpent,
        pendingCredits: wallet.pendingCredits
      });
    } else {
      res.json({ balance: 750, credits: 750 }); // Default demo values
    }
  } catch (error) {
    console.error('Wallet balance error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Custom unlock key route
server.post('/api/unlock/:keyId', async (req, res) => {
  try {
    const keyId = req.params.keyId;

    const [keys] = await pool.execute(
      'SELECT * FROM createdKeys WHERE id = ?',
      [parseInt(keyId)]
    );

    const key = keys[0];

    if (key && key.available > 0) {
      // Simulate random key from available pool
      const keyVariations = [
        `${key.keyValue}-${Math.random().toString(36).substring(2, 8).toUpperCase()}`,
        `${key.keyValue.replace('ABCD', Math.random().toString(36).substring(2, 6).toUpperCase())}`,
        key.keyValue
      ];

      const randomKey = keyVariations[Math.floor(Math.random() * keyVariations.length)];

      // Update availability
      await pool.execute(
        'UPDATE createdKeys SET available = available - 1, sold = sold + 1 WHERE id = ?',
        [parseInt(keyId)]
      );

      // Create unlock record
      const transactionId = Math.floor(Math.random() * 10000);

      await pool.execute(
        'INSERT INTO unlocks (transactionId, username, email, date, time, credits, keyId, keyTitle, keyValue, sellerUsername, sellerEmail, price, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [
          transactionId,
          'user_123', // Demo user
          'john.buyer@example.com',
          Date.now(),
          new Date().toLocaleTimeString(),
          750,
          key.keyId,
          key.keyTitle,
          randomKey,
          key.username,
          key.email,
          key.price,
          'Completed'
        ]
      );

      res.json({
        success: true,
        key: randomKey,
        transactionId: transactionId
      });
    } else {
      res.status(404).json({ success: false, message: 'Key not available or not found' });
    }
  } catch (error) {
    console.error('Unlock key error:', error);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

// Custom route for seller listings
server.get('/api/seller/listings/:id', async (req, res) => {
  try {
    const id = req.params.id;

    const [keys] = await pool.execute(
      'SELECT * FROM createdKeys WHERE id = ?',
      [parseInt(id)]
    );

    const key = keys[0];

    if (key) {
      res.json(key);
    } else {
      res.status(404).json({ error: 'Listing not found' });
    }
  } catch (error) {
    console.error('Seller listing error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Custom route for all listings
server.get('/api/listings', async (req, res) => {
  try {
    const [listings] = await pool.execute(
      'SELECT * FROM createdKeys WHERE isActive = true'
    );
    res.json(listings);
  } catch (error) {
    console.error('Listings error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Custom route for user notifications
server.get('/api/notifications/:username', async (req, res) => {
  try {
    const username = req.params.username;

    const [notifications] = await pool.execute(
      'SELECT * FROM notifications WHERE username = ? ORDER BY createdAt DESC',
      [username]
    );

    res.json(notifications);
  } catch (error) {
    console.error('Notifications error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Custom route for create key
server.post('/api/create-key', async (req, res) => {
  try {
    const { title, price_credits } = req.body;

    // Simulate file processing
    setTimeout(async () => {
      try {
        const keyId = `key_${Date.now()}`;
        const quantity = Math.floor(Math.random() * 50) + 10;

        await pool.execute(
          'INSERT INTO createdKeys (keyId, username, email, keyTitle, keyValue, description, price, quantity, sold, available, creationDate, expirationDate, isActive, isReported, reportCount, encryptionKey, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
          [
            keyId,
            'seller_123',
            'jane.seller@example.com',
            title || 'New Key Listing',
            `DEMO-KEY-${Math.random().toString(36).substring(2, 8).toUpperCase()}`,
            `Generated key listing: ${title}`,
            parseInt(price_credits) || 100,
            quantity,
            0,
            quantity,
            Date.now(),
            null,
            true,
            false,
            0,
            `enc_key_${Date.now()}`,
            JSON.stringify(['demo', 'uploaded'])
          ]
        );

        res.json({
          success: true,
          uploadId: keyId,
          message: 'Keys uploaded successfully'
        });
      } catch (error) {
        console.error('Create key error:', error);
        res.status(500).json({ success: false, message: 'Database error' });
      }
    }, 1000);
  } catch (error) {
    console.error('Create key outer error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

//  const newUser = {
        //   loginStatus: true,
        //   lastLogin: new Date().toISOString(),
        //   accountType: accountType || 'buyer',
        //   username: username,
        //   email: email,
        //   firstName: name.split(' ')[0] || name,
        //   lastName: name.split(' ').slice(1).join(' ') || '',
        //   phoneNumber: '',
        //   birthDate: birthday,
        //   encryptionKey: `enc_key_${Date.now()}`,
        //   credits: 100, // Starting credits
        //   reportCount: 0,
        //   isBanned: false,
        //   banReason: '',
        //   banDate: null,
        //   banDuration: null,
        //   createdAt: Date.now(),
        //   updatedAt: Date.now(),
        //   passwordHash: '$2b$10$hashedpassword', // Demo hash
        //   twoFactorEnabled: false,
        //   twoFactorSecret: '',
        //   recoveryCodes: [],
        //   profilePicture: `https://i.pravatar.cc/150?img=${Math.floor(Math.random() * 70) + 1}`,
        //   bio: '',
        //   socialLinks: {
        //     facebook: '',
        //     twitter: '',
        //     instagram: '',
        //     linkedin: '',
        //     website: ''
        //   }
        // };

// // Create user in JSON server
// const response = await fetch('http://localhost:3001/api/userData', {
//   method: 'POST',
//   headers: {
//     'Content-Type': 'application/json',
//   },
//   body: JSON.stringify(newUser)
// });

server.post('/api/userData', async (req, res) => {
  try {
    const newUser = req.body;

    console.log('Creating new user:', newUser);

    // Helper function to convert ISO datetime to MySQL format
    const formatDateTimeForMySQL = (dateTime) => {
      if (!dateTime) return null;
      if (typeof dateTime === 'string') {
        // Convert ISO 8601 to MySQL datetime format (YYYY-MM-DD HH:mm:ss)
        return new Date(dateTime).toISOString().slice(0, 19).replace('T', ' ');
      }
      if (typeof dateTime === 'number') {
        // Convert timestamp to MySQL datetime format
        return new Date(dateTime).toISOString().slice(0, 19).replace('T', ' ');
      }
      return null;
    };

    // Generate a unique ID (since the schema uses VARCHAR(10))
    const generateId = () => {
      return Math.random().toString(36).substring(2, 8); // Generates a 6-character random string
    };

    const userId = newUser.id || generateId();

    const [result] = await pool.execute(
      'INSERT INTO userData (id, loginStatus, lastLogin, accountType, username, email, firstName, lastName, phoneNumber, birthDate, encryptionKey, credits, reportCount, isBanned, banReason, banDate, banDuration, createdAt, updatedAt, passwordHash, twoFactorEnabled, twoFactorSecret, recoveryCodes, profilePicture, bio, socialLinks) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [
        userId,
        newUser.loginStatus,
        formatDateTimeForMySQL(newUser.lastLogin),
        newUser.accountType,
        newUser.username,
        newUser.email,
        newUser.firstName,
        newUser.lastName,
        newUser.phoneNumber,
        newUser.birthDate, // This should already be in YYYY-MM-DD format
        newUser.encryptionKey,
        newUser.credits,
        newUser.reportCount,
        newUser.isBanned,
        newUser.banReason,
        formatDateTimeForMySQL(newUser.banDate),
        newUser.banDuration,
        newUser.createdAt, // Keep as timestamp (BIGINT)
        newUser.updatedAt, // Keep as timestamp (BIGINT)
        newUser.passwordHash,
        newUser.twoFactorEnabled,
        newUser.twoFactorSecret,
        JSON.stringify(newUser.recoveryCodes || []),
        newUser.profilePicture,
        newUser.bio,
        JSON.stringify(newUser.socialLinks || {})
      ]
    );
    res.json({ success: true, id: userId });
   
  } catch (error) {
    console.error('Create user error:', error); 
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

// Custom route for user purchases
server.get('/api/purchases/:username', async (req, res) => {
  try {
    const username = req.params.username;

    const [purchases] = await pool.execute(
      'SELECT * FROM buyCredits WHERE username = ? ORDER BY date DESC',
      [username]
    );

    res.json(purchases);
  } catch (error) {
    console.error('Purchases error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Custom route for user redemptions
server.get('/api/redemptions/:username', async (req, res) => {
  try {
    const username = req.params.username;

    const [redemptions] = await pool.execute(
      'SELECT * FROM redeemCredits WHERE username = ? ORDER BY date DESC',
      [username]
    );

    res.json(redemptions);
  } catch (error) {
    console.error('Redemptions error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});



// Basic RESTful routes for all tables
server.get('/api/:table', async (req, res) => {
  try {
    const table = req.params.table;
    const allowedTables = ['userData', 'buyCredits', 'redeemCredits', 'earnings', 'unlocks', 'createdKeys', 'notifications', 'wallet', 'reports', 'supportTickets'];

    if (!allowedTables.includes(table)) {
      return res.status(400).json({ error: 'Invalid table name' });
    }

    const [rows] = await pool.execute(`SELECT * FROM ${table}`);
    res.json(rows);
  } catch (error) {
    console.error(`Get ${req.params.table} error:`, error);
    res.status(500).json({ error: 'Database error' });
  }
});

server.get('/api/:table/:id', async (req, res) => {
  try {
    const { table, id } = req.params;
    const allowedTables = ['userData', 'buyCredits', 'redeemCredits', 'earnings', 'unlocks', 'createdKeys', 'notifications', 'wallet', 'reports', 'supportTickets'];

    if (!allowedTables.includes(table)) {
      return res.status(400).json({ error: 'Invalid table name' });
    }

    const [rows] = await pool.execute(`SELECT * FROM ${table} WHERE id = ?`, [id]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Record not found' });
    }

    res.json(rows[0]);
  } catch (error) {
    console.error(`Get ${req.params.table} by ID error:`, error);
    res.status(500).json({ error: 'Database error' });
  }
});

server.patch('/api/:table/:id', async (req, res) => {
  try {
    const { table, id } = req.params;
    const allowedTables = ['userData', 'buyCredits', 'redeemCredits', 'earnings', 'unlocks', 'createdKeys', 'notifications', 'wallet', 'reports', 'supportTickets'];

    if (!allowedTables.includes(table)) {
      return res.status(400).json({ error: 'Invalid table name' });
    }

    const updateData = req.body;
    const columns = Object.keys(updateData);
    const values = Object.values(updateData);

    if (columns.length === 0) {
      return res.status(400).json({ error: 'No data to update' });
    }

    const setClause = columns.map(col => `${col} = ?`).join(', ');
    const query = `UPDATE ${table} SET ${setClause} WHERE id = ?`;

    const [result] = await pool.execute(query, [...values, id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Record not found' });
    }

    // Get updated record
    const [updated] = await pool.execute(`SELECT * FROM ${table} WHERE id = ?`, [id]);
    res.json(updated[0]);
  } catch (error) {
    console.error(`Update ${req.params.table} error:`, error);
    res.status(500).json({ error: 'Database error' });
  }
});



// Global error handler
server.use((error, req, res, next) => {
  console.error('Global error handler:', error);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
  });
});

// 404 handler for undefined routes
server.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, async () => {
  try {
    // Test database connection
    await pool.execute('SELECT 1');
    console.log('🚀 Express Server with MySQL is running on port', PORT);
    console.log('�️  Database: KeyChingDB (MySQL)');
    console.log('🌐 API Base URL: http://localhost:' + PORT + '/api');
    console.log('📋 Available endpoints:');
    console.log('   - GET /api/userData');
    console.log('   - GET /api/createdKeys');
    console.log('   - GET /api/unlocks/:username');
    console.log('   - GET /api/purchases/:username');
    console.log('   - GET /api/redemptions/:username');
    console.log('   - GET /api/notifications/:username');
    console.log('   - POST /api/auth/login');
    console.log('   - GET /api/wallet/balance');
    console.log('   - POST /api/unlock/:keyId');
    console.log('   - GET /api/listings');
    console.log('   - POST /api/create-key');
    console.log('   - GET /api/:table');
    console.log('   - GET /api/:table/:id');
    console.log('   - PATCH /api/:table/:id');
  } catch (error) {
    console.error('❌ Failed to connect to MySQL database:', error.message);
    console.log('📝 Please ensure:');
    console.log('   1. MySQL server is running');
    console.log('   2. KeyChingDB database exists');
    console.log('   3. Database credentials are correct in server.cjs');
    process.exit(1);
  }
});
// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('🛑 Received SIGTERM, shutting down gracefully...');
  await pool.end();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('🛑 Received SIGINT, shutting down gracefully...');
  await pool.end();
  process.exit(0);
});
