import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';

const host = process.env.OP_DB_HOST;
const user = process.env.OP_DB_USER;
const password = process.env.OP_DB_PASS;
const database = process.env.OP_DB_NAME;

let dbPool = null;
async function ensureDb() {
  if (!dbPool) {
    dbPool = mysql.createPool({ host, user, password, database, waitForConnections: true, connectionLimit: 5, queueLimit: 0 });
  }
  return dbPool;
}

function json(res, status, data) {
  res.status(status).json(data);
}

export async function handleGetData(req, res, payload) {
  const pool = await ensureDb();
  const action = payload.action;

  if (action === 'login') {
    try {
      const body = payload.payload || payload;
      const username = body?.username;
      const plainPassword = body?.password;
      if (!username || !plainPassword) {
        return json(res, 400, { success: false, message: 'Username dan password wajib diisi.' });
      }
      const usersRes = await pool.query('SELECT * FROM users WHERE username = ? LIMIT 1', [username]);
      const rows = usersRes?.[0] || [];
      if (!rows.length) {
        return json(res, 401, { success: false, message: 'Username atau password salah.' });
      }
      const row = rows[0];
      const storedPassword = row.password || row.pass || '';
      let isMatch = false;
      if (storedPassword) {
        if (storedPassword.startsWith('$2a$') || storedPassword.startsWith('$2b$') || storedPassword.startsWith('$2y$')) {
          try {
            isMatch = await bcrypt.compare(plainPassword, storedPassword);
          } catch (e) {
            isMatch = false;
          }
        } else if (/^[a-f0-9]{32}$/i.test(storedPassword)) {
          const md5 = crypto.createHash('md5').update(plainPassword).digest('hex');
          isMatch = md5 === storedPassword;
        } else {
          isMatch = storedPassword === plainPassword;
        }
      }
      if (!isMatch) {
        return json(res, 401, { success: false, message: 'Username atau password salah.' });
      }
      const userObj = {
        id: row.id,
        username: row.username,
        email: row.email,
        role: row.role,
        status: row.status,
        clientId: row.clientId || row.client_id || null
      };
      return json(res, 200, { success: true, user: userObj });
    } catch (e) {
      console.error('Error during login:', e);
      return json(res, 500, { success: false, message: 'Terjadi kesalahan saat login.' });
    }
  } else if (action === 'get_public_data') {
    let settingsObj = {};
    try {
      const colsRes = await pool.query("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'site_settings'");
      const cols = (colsRes?.[0] || []).map((r) => String(r.COLUMN_NAME));
      const colKey = cols.includes('setting_key') ? 'setting_key' : (cols.includes('key') ? 'key' : 'key');
      const colVal = cols.includes('setting_value') ? 'setting_value' : (cols.includes('value') ? 'value' : 'value');
      const settingsRows = await pool.query(`SELECT \`${colKey}\` as k, \`${colVal}\` as v FROM \`site_settings\``);
      const rows = settingsRows?.[0] || [];
      for (const r of rows) {
        const k = (r.k || '').toString();
        let v = r.v;
        if (!k) continue;
        if (typeof v === 'string' && (v.trim().startsWith('{') || v.trim().startsWith('['))) {
          try { v = JSON.parse(v) } catch {}
        }
        const parts = k.split('.');
        let cursor = settingsObj;
        for (let i = 0; i < parts.length; i++) {
          const p = parts[i];
          if (i === parts.length - 1) cursor[p] = v;
          else { cursor[p] = cursor[p] || {}; cursor = cursor[p] }
        }
      }
      const packages = await pool.query("SELECT * FROM hosting_packages");
      return json(res, 200, { success: true, data: { settings: settingsObj, hostingPackages: packages[0] } });
    } catch (e) {
      console.error('Error fetching public data:', e);
      return json(res, 500, { success: false, message: 'Database error while fetching public data.' });
    }
  } else if (action === 'get_dashboard_data') {
    const user = payload.user;
    if (!user || !user.id) {
        return json(res, 401, { success: false, message: 'Authentication required.' });
    }
    try {
        const clientColsRes = await pool.query("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'clients'");
        const clientCols = (clientColsRes?.[0] || []).map((r) => String(r.COLUMN_NAME));
        const colClientName =
          clientCols.includes('fullName') ? 'fullName' :
          clientCols.includes('full_name') ? 'full_name' :
          clientCols.includes('name') ? 'name' :
          clientCols.includes('nama') ? 'nama' :
          clientCols[0] || 'id';

        const websites = await pool.query(
          `SELECT w.*, c.\`${colClientName}\` as clientName, p.name as packageName
           FROM websites w
           LEFT JOIN clients c ON w.clientId = c.id
           LEFT JOIN hosting_packages p ON w.packageId = p.id
           ORDER BY w.id DESC`
        );
        const clients = await pool.query("SELECT * FROM clients ORDER BY id DESC");
        const invoices = await pool.query(
          `SELECT i.*, c.\`${colClientName}\` as clientName, w.domain
           FROM invoices i
           LEFT JOIN clients c ON i.clientId = c.id
           LEFT JOIN websites w ON i.websiteId = w.id
           ORDER BY i.id DESC`
        );
        const hostingPackages = await pool.query("SELECT * FROM hosting_packages ORDER BY monthly_price_idr ASC");
        const registrations = await pool.query("SELECT r.*, p.name as packageName FROM registrations r LEFT JOIN hosting_packages p ON r.packageId = p.id ORDER BY r.id DESC");
        let settingsObj = {};
        const data = {
            websites: websites[0],
            clients: clients[0],
            invoices: invoices[0],
            hostingPackages: hostingPackages[0],
            registrations: registrations[0],
            settings: settingsObj,
        };
        if (user.role === 'superadmin') {
            const users = await pool.query("SELECT id, username, email, role, lastLogin, status FROM users ORDER BY id DESC");
            data.users = users[0];
        }
        return json(res, 200, { success: true, data });
    } catch (e) {
        console.error('Error fetching dashboard data:', e);
        return json(res, 500, { success: false, message: 'Database error while fetching dashboard data.' });
    }
  }

  return json(res, 400, { success: false, message: 'Invalid data action.' });
}

export async function handleUpdateData(req, res, payload) {
  const pool = await ensureDb();
  const user = payload?.user;
  const action = payload?.action;
  const data = payload?.payload || {};
  if (!user || !action) return json(res, 400, { success: false, message: 'Invalid request structure.' });
  const role = String(user.role || '').toLowerCase();
  if (!['superadmin','admin','support'].includes(role) && action !== 'update_password') return json(res, 403, { success: false, message: 'Permission denied.' });
  
  // Add your update logic here based on 'action'
  
  return json(res, 400, { success: false, message: 'Invalid update action.' });
}
