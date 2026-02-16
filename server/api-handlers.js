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

function normalizeHostingPackages(rows) {
  return rows.map((row) => {
    let features = row.features;
    if (Array.isArray(features)) {
      return row;
    }
    let parsed = [];
    if (typeof features === 'string') {
      const trimmed = features.trim();
      if (trimmed) {
        if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
          try {
            const jsonVal = JSON.parse(trimmed);
            if (Array.isArray(jsonVal)) {
              parsed = jsonVal.filter((v) => typeof v === 'string' && v.trim() !== '');
            }
          } catch (e) {
          }
        }
        if (!parsed.length) {
          parsed = trimmed
            .split(/\r?\n|;|,/)
            .map((s) => s.trim())
            .filter((s) => s.length > 0);
        }
      }
    }
    return { ...row, features: parsed };
  });
}

function parseDiskUsageToMb(val) {
  if (val == null) return 0;
  if (typeof val === 'number') {
    if (!isNaN(val) && val >= 0) return val;
    return 0;
  }
  let s = String(val).trim();
  if (!s) return 0;
  const match = s.match(/^([\d.,]+)\s*([A-Za-z]+)?$/);
  if (!match) {
    const num = parseFloat(s.replace(',', '.'));
    return !isNaN(num) && num >= 0 ? num : 0;
  }
  const num = parseFloat(match[1].replace(',', '.'));
  if (isNaN(num) || num < 0) return 0;
  const unitRaw = (match[2] || 'MiB').toUpperCase();
  if (unitRaw.startsWith('T')) return num * 1024 * 1024;
  if (unitRaw.startsWith('G')) return num * 1024;
  if (unitRaw.startsWith('K')) return num / 1024;
  return num;
}

function normalizeWebsites(rows) {
  return rows.map((row) => {
    const diskVal = row.disk_usage_mb != null ? row.disk_usage_mb : (row.disk_usage != null ? row.disk_usage : null);
    const disk_usage_mb = parseDiskUsageToMb(diskVal);
    let inodes = row.inodes;
    inodes = typeof inodes === 'number' ? inodes : parseInt(inodes, 10);
    if (isNaN(inodes) || inodes < 0) inodes = 0;
    let parentId = row.parentId;
    if (parentId === '' || parentId == null) parentId = null;
    else {
      const pid = parseInt(parentId, 10);
      parentId = isNaN(pid) ? null : pid;
    }
    const last_modified = row.last_modified || row.last_updated || row.lastUpdate || '';
    return { 
      ...row, 
      disk_usage_mb, 
      inodes, 
      parentId,
      last_modified 
    };
  });
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
      const packages = await pool.query("SELECT * FROM hosting_packages ORDER BY monthly_price_idr ASC");
      const packageRows = packages?.[0] || [];
      const normalizedPackages = normalizeHostingPackages(packageRows);
      return json(res, 200, { success: true, data: { settings: settingsObj, hostingPackages: normalizedPackages } });
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

        const websiteColsRes = await pool.query("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'websites'");
        const websiteCols = (websiteColsRes?.[0] || []).map((r) => String(r.COLUMN_NAME));
        const colWebsiteClientId =
          websiteCols.includes('clientId') ? 'clientId' :
          websiteCols.includes('client_id') ? 'client_id' :
          websiteCols.includes('client') ? 'client' :
          websiteCols[0] || 'id';
        const colWebsitePackageId =
          websiteCols.includes('packageId') ? 'packageId' :
          websiteCols.includes('package_id') ? 'package_id' :
          websiteCols.includes('hosting_package_id') ? 'hosting_package_id' :
          websiteCols[0] || 'id';
        const colWebsiteDomain =
          websiteCols.includes('domain') ? 'domain' :
          websiteCols.includes('domain_name') ? 'domain_name' :
          websiteCols.includes('url') ? 'url' :
          websiteCols.includes('hostname') ? 'hostname' :
          websiteCols[0] || 'id';

        const colDiskUsage = 
          websiteCols.includes('disk_usage_mb') ? 'disk_usage_mb' :
          websiteCols.includes('diskUsageMb') ? 'diskUsageMb' :
          websiteCols.includes('disk_usage') ? 'disk_usage' :
          'disk_usage_mb';

        const colInodes = 
          websiteCols.includes('inodes') ? 'inodes' :
          websiteCols.includes('inode_usage') ? 'inode_usage' :
          'inodes';

        const invoiceColsRes = await pool.query("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'invoices'");
        const invoiceCols = (invoiceColsRes?.[0] || []).map((r) => String(r.COLUMN_NAME));
        const colInvoiceClientId =
          invoiceCols.includes('clientId') ? 'clientId' :
          invoiceCols.includes('client_id') ? 'client_id' :
          invoiceCols.includes('client') ? 'client' :
          invoiceCols[0] || 'id';
        const colInvoiceWebsiteId =
          invoiceCols.includes('websiteId') ? 'websiteId' :
          invoiceCols.includes('website_id') ? 'website_id' :
          invoiceCols.includes('site_id') ? 'site_id' :
          invoiceCols[0] || 'id';

        const websites = await pool.query(
          `SELECT w.*, 
           w.\`${colDiskUsage}\` as disk_usage,
           w.\`${colInodes}\` as inodes,
           c.\`${colClientName}\` as clientName, p.name as packageName
           FROM websites w
           LEFT JOIN clients c ON w.\`${colWebsiteClientId}\` = c.id
           LEFT JOIN hosting_packages p ON w.\`${colWebsitePackageId}\` = p.id
           ORDER BY w.id DESC`
        );
        const clients = await pool.query("SELECT * FROM clients ORDER BY id DESC");
        const invoices = await pool.query(
          `SELECT i.*, c.\`${colClientName}\` as clientName, w.\`${colWebsiteDomain}\` as domain
           FROM invoices i
           LEFT JOIN clients c ON i.\`${colInvoiceClientId}\` = c.id
           LEFT JOIN websites w ON i.\`${colInvoiceWebsiteId}\` = w.id
           ORDER BY i.id DESC`
        );
        const hostingPackagesRes = await pool.query("SELECT * FROM hosting_packages ORDER BY monthly_price_idr ASC");
        const registrations = await pool.query("SELECT r.*, p.name as packageName FROM registrations r LEFT JOIN hosting_packages p ON r.packageId = p.id ORDER BY r.id DESC");
        let settingsObj = {};
        const data = {
            websites: normalizeWebsites(websites[0] || []),
            clients: clients[0],
            invoices: invoices[0],
            hostingPackages: normalizeHostingPackages(hostingPackagesRes?.[0] || []),
            registrations: registrations[0],
            settings: settingsObj,
        };
        if (user.role === 'superadmin') {
            const userColsRes = await pool.query("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'");
            const userCols = (userColsRes?.[0] || []).map((r) => String(r.COLUMN_NAME));
            const colLastLogin =
              userCols.includes('lastLogin') ? 'lastLogin' :
              userCols.includes('last_login') ? 'last_login' :
              userCols.includes('last_login_at') ? 'last_login_at' :
              null;
            let selectUser =
              "id, username, email, role, status" +
              (colLastLogin ? `, \`${colLastLogin}\` as lastLogin` : ", NULL as lastLogin");
            const users = await pool.query(`SELECT ${selectUser} FROM users ORDER BY id DESC`);
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
  if (!['superadmin','admin','support'].includes(role) && action !== 'update_password') {
    return json(res, 403, { success: false, message: 'Permission denied.' });
  }

  if (action === 'update_site_settings') {
    if (role !== 'superadmin') {
      return json(res, 403, { success: false, message: 'Only superadmin can update site settings.' });
    }
    try {
      const colsRes = await pool.query(
        "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'site_settings'"
      );
      const cols = (colsRes?.[0] || []).map((r) => String(r.COLUMN_NAME));
      const colKey = cols.includes('setting_key') ? 'setting_key' : (cols.includes('key') ? 'key' : 'key');
      const colVal = cols.includes('setting_value') ? 'setting_value' : (cols.includes('value') ? 'value' : 'value');

      const existingRes = await pool.query(`SELECT \`${colKey}\` as k FROM \`site_settings\``);
      const existingRows = existingRes?.[0] || [];
      const existingKeys = new Set(existingRows.map((r) => String(r.k)));

      const settings = data || {};
      const pairs = [];
      const general = settings.general || {};
      pairs.push(['general.siteName', general.siteName || '']);
      pairs.push(['general.heroTitle', general.heroTitle || '']);
      pairs.push(['general.heroSubtitle', general.heroSubtitle || '']);
      pairs.push(['general.heroButtonText', general.heroButtonText || '']);

      const navigation = settings.navigation || {};
      pairs.push(['navigation.headerLinks', navigation.headerLinks || []]);

      const contact = settings.contact || {};
      pairs.push(['contact.whatsappNumber', contact.whatsappNumber || '']);
      pairs.push(['contact.whatsappDefaultMessage', contact.whatsappDefaultMessage || '']);

      const footer = settings.footer || {};
      pairs.push(['footer.slogan', footer.slogan || '']);
      pairs.push(['footer.copyrightName', footer.copyrightName || '']);
      pairs.push(['footer.linkColumns', footer.linkColumns || []]);

      const packagesPage = settings.packagesPage || {};
      pairs.push(['packagesPage.title', packagesPage.title || '']);
      pairs.push(['packagesPage.subtitle', packagesPage.subtitle || '']);
      pairs.push(['packagesPage.faq', packagesPage.faq || []]);

      for (const [key, rawVal] of pairs) {
        let v = rawVal;
        if (v === undefined) continue;
        if (v === null) v = '';
        if (typeof v === 'object') {
          try {
            v = JSON.stringify(v);
          } catch {
            v = '';
          }
        } else {
          v = String(v);
        }
        if (existingKeys.has(key)) {
          await pool.query(
            `UPDATE \`site_settings\` SET \`${colVal}\` = ? WHERE \`${colKey}\` = ? LIMIT 1`,
            [v, key]
          );
        } else {
          await pool.query(
            `INSERT INTO \`site_settings\` (\`${colKey}\`, \`${colVal}\`) VALUES (?, ?)`,
            [key, v]
          );
        }
      }

      return json(res, 200, { success: true });
    } catch (e) {
      console.error('Error updating site settings:', e);
      return json(res, 500, { success: false, message: 'Database error while updating site settings.' });
    }
  }

  return json(res, 400, { success: false, message: 'Invalid update action.' });
}
