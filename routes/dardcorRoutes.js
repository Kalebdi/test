const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const supabase = require('../config/supabase');
const { v4: uuidv4, validate: uuidValidate } = require('uuid');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const { handleChatStream } = require('../controllers/dardcorModel');
const { YoutubeTranscript } = require('youtube-transcript');
const cheerio = require('cheerio');
const axios = require('axios');
const mammoth = require('mammoth');
const xlsx = require('xlsx');
const path = require('path');
const fs = require('fs');
const fsPromises = require('fs').promises;
const os = require('os');
const dns = require('dns');
const crypto = require('crypto');
const { URL } = require('url');

if (!process.env.SESSION_SECRET) {
    throw new Error('SESSION_SECRET environment variable is required.');
}

const STATIC_KEY = process.env.SESSION_SECRET;
const SESSION_DURATION = 3155760000000;

const upload = multer({
    storage: multer.diskStorage({
        destination: os.tmpdir(),
        filename: (req, file, cb) => {
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
            cb(null, `${uniqueSuffix}-${file.originalname.replace(/[^a-zA-Z0-9.-]/g, '')}`);
        }
    }),
    limits: { fileSize: 100 * 1024 * 1024, files: 10 }
});

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Too many authentication attempts, please try again later.' }
});

const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false
});

const securityMiddleware = (req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-XSS-Protection', '0');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
};

router.use(cookieParser());
router.use(securityMiddleware);

const uploadMiddleware = (req, res, next) => {
    upload.array('file_attachment', 10)(req, res, function (err) {
        if (err) return res.status(400).json({ success: false, message: "Upload Error: " + err.message });
        next();
    });
};

function generateAuthToken(user) {
    const payload = JSON.stringify({
        id: user.id,
        email: user.email,
        v: user.password.substring(0, 20),
        ts: Date.now(),
        jti: uuidv4()
    });
    const signature = crypto.createHmac('sha512', STATIC_KEY).update(payload).digest('hex');
    return Buffer.from(`${payload}.${signature}`).toString('base64');
}

function verifyAuthToken(token) {
    try {
        const decoded = Buffer.from(token, 'base64').toString('utf-8');
        const parts = decoded.split('.');
        if (parts.length !== 2) return null;
        
        const payloadStr = parts[0];
        const signature = parts[1];
        
        const expectedSignature = crypto.createHmac('sha512', STATIC_KEY).update(payloadStr).digest('hex');
        
        const sigBuffer = Buffer.from(signature);
        const expectedBuffer = Buffer.from(expectedSignature);

        if (sigBuffer.length !== expectedBuffer.length) return null;
        if (!crypto.timingSafeEqual(sigBuffer, expectedBuffer)) return null;
        
        return JSON.parse(payloadStr);
    } catch (e) {
        return null;
    }
}

const cookieConfig = {
    maxAge: SESSION_DURATION,
    httpOnly: true,
    path: '/',
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
};

async function handleLoginCheck(req, res, renderPage) {
    if (req.session && req.session.userAccount) {
        return res.redirect('/loading');
    }
    const authCookie = req.cookies['dardcor_perm_auth'];
    if (!authCookie) {
        return res.render(renderPage, { error: null, user: null, email: req.query.email || '' });
    }
    const userData = verifyAuthToken(authCookie);
    if (!userData) {
        res.clearCookie('dardcor_perm_auth');
        return res.render(renderPage, { error: null, user: null, email: req.query.email || '' });
    }
    try {
        const { data: user, error } = await supabase.from('dardcor_users').select('*').eq('id', userData.id).maybeSingle();
        if (!error && user && user.password.substring(0, 20) === userData.v) {
            req.session.userAccount = user;
            req.session.cookie.maxAge = SESSION_DURATION;
            res.cookie('dardcor_perm_auth', generateAuthToken(user), cookieConfig);
            return req.session.save(() => {
                res.redirect('/loading');
            });
        }
        res.clearCookie('dardcor_perm_auth');
        return res.render(renderPage, { error: null, user: null, email: req.query.email || '' });
    } catch (e) {
        return res.render(renderPage, { error: null, user: null, email: req.query.email || '' });
    }
}

// --- BAGIAN MIDDLEWARE PROTECTED ROUTE (DIUBAH TOTAL) ---

async function protectedRoute(req, res, next) {
    // 1. Jika sudah login secara normal
    if (req.session && req.session.userAccount) {
        return next();
    }

    // 2. Cek Cookie Auth (Permanen)
    const authCookie = req.cookies['dardcor_perm_auth'];
    if (authCookie) {
        const userData = verifyAuthToken(authCookie);
        if (userData) {
            try {
                const { data: user } = await supabase.from('dardcor_users').select('*').eq('id', userData.id).maybeSingle();
                if (user && user.password.substring(0, 20) === userData.v) {
                    req.session.userAccount = user;
                    return req.session.save(() => next());
                }
            } catch (e) { /* lanjut ke guest mode */ }
        }
    }

    // 3. FULL FIX: GUEST MODE (Jika tidak ada login, buat session sementara)
    req.session.userAccount = {
        id: '00000000-0000-0000-0000-000000000000', // ID dummy untuk Guest
        username: 'Guest_' + Math.floor(1000 + Math.random() * 9000),
        email: 'guest@dardcor.ai',
        profile_image: '/logo.png' // Default logo
    };
    
    next(); 
}

// --- BAGIAN LOGIN CHECK UNTUK HALAMAN DEPAN (DIUBAH) ---

async function handleLoginCheck(req, res, renderPage) {
    // Jika sudah ada session user asli (bukan guest dummy), pindah ke loading
    if (req.session && req.session.userAccount && req.session.userAccount.id !== '00000000-0000-0000-0000-000000000000') {
        return res.redirect('/loading');
    }
    
    // Jika belum login, tampilkan halaman (index/dardcor/register) tanpa redirect paksa
    return res.render(renderPage, { error: null, user: null, email: req.query.email || '' });
}

// --- BAGIAN ROUTE (DIPASTIKAN TERBUKA) ---

// Halaman utama sekarang bisa diakses walau tanpa login
router.get('/', (req, res) => {
    // Kita buat agar '/' langsung masuk ke chat sebagai guest jika ingin instan
    res.redirect('/dardcorchat/dardcor-ai'); 
});

// Endpoint Chat API (Sekarang menggunakan protectedRoute yang sudah mendukung Guest)
router.post('/dardcorchat/ai/chat-stream', protectedRoute, uploadMiddleware, async (req, res) => {
    // ... isi code stream kamu tetap sama ...
    // Karena protectedRoute sudah memberikan object Guest ke req.session.userAccount,
    // maka variabel userId di dalam sini tidak akan undefined.
});

// Tambahan: Pastikan database 'conversations' & 'history_chat' mengizinkan user_id dummy 
// atau kamu bisa memodifikasi logika insert-nya:

/* Di dalam router.post('/dardcorchat/ai/chat-stream'), 
pastikan saat insert ke Supabase, kamu menangani user_id guest:
*/

// Contoh modifikasi di dalam stream:
const userId = req.session.userAccount.id; 
// Jika userId adalah '00000000...', pastikan tabel di Supabase tidak me-reject-nya (non-foreign key error)
                                       

async function isSafeUrl(urlString) {
    try {
        const parsed = new URL(urlString);
        if (!['http:', 'https:'].includes(parsed.protocol)) return false;
        const hostname = parsed.hostname;
        
        if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1' || hostname === '0.0.0.0') return false;
        
        return new Promise((resolve) => {
            dns.lookup(hostname, { all: true }, (err, addresses) => {
                if (err || !addresses || addresses.length === 0) return resolve(false);
                for (const addr of addresses) {
                    const ip = addr.address;
                    if (ip.includes(':')) {
                        if (ip === '::1' || ip === '::' || ip.startsWith('fc') || ip.startsWith('fd')) return resolve(false);
                    } else {
                        const parts = ip.split('.').map(Number);
                        if (parts[0] === 10) return resolve(false);
                        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return resolve(false);
                        if (parts[0] === 192 && parts[1] === 168) return resolve(false);
                        if (parts[0] === 169 && parts[1] === 254) return resolve(false);
                        if (parts[0] === 127) return resolve(false);
                    }
                }
                resolve(true);
            });
        });
    } catch (e) {
        return false;
    }
}

async function parsePdfSafe(buffer) {
    const globalBackup = {
        DOMMatrix: global.DOMMatrix,
        ImageData: global.ImageData,
        Path2D: global.Path2D,
        window: global.window
    };

    try {
        if (!global.DOMMatrix) global.DOMMatrix = class DOMMatrix {};
        if (!global.ImageData) global.ImageData = class ImageData {};
        if (!global.Path2D) global.Path2D = class Path2D {};
        if (!global.window) global.window = global;

        const pdfjs = await import('pdfjs-dist/legacy/build/pdf.mjs');
        const data = new Uint8Array(buffer);
        const loadingTask = pdfjs.getDocument({
            data: data,
            useSystemFonts: true,
            disableFontFace: true,
            verbosity: 0
        });

        const pdf = await loadingTask.promise;
        let fullText = "";
        
        for (let i = 1; i <= pdf.numPages; i++) {
            try {
                const page = await pdf.getPage(i);
                const textContent = await page.getTextContent();
                const pageText = textContent.items.map(item => item.str).join(' ');
                fullText += `[PAGE ${i}]: ${pageText}\n`;
            } catch (pageErr) {
                continue;
            }
        }
        return fullText.trim() || "[PDF EMPTY]";
    } catch (error) {
        return "[PDF PARSE ERROR]";
    } finally {
        if (globalBackup.DOMMatrix === undefined) delete global.DOMMatrix; else global.DOMMatrix = globalBackup.DOMMatrix;
        if (globalBackup.ImageData === undefined) delete global.ImageData; else global.ImageData = globalBackup.ImageData;
        if (globalBackup.Path2D === undefined) delete global.Path2D; else global.Path2D = globalBackup.Path2D;
        if (globalBackup.window === undefined) delete global.window; else global.window = globalBackup.window;
    }
}

async function sendDiscordError(context, error) {
    const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
    if (!webhookUrl) return;
    try {
        await axios.post(webhookUrl, {
            username: "Dardcor Monitor",
            embeds: [{
                title: `System Alert: ${context}`,
                description: `\`\`\`${String(error?.message || error).substring(0, 1500)}\`\`\``,
                color: 16711680,
                timestamp: new Date().toISOString(),
                footer: { text: "Dardcor AI Core" }
            }]
        });
    } catch (e) {}
}

async function getYouTubeData(url) {
    if (!await isSafeUrl(url)) return { success: false };
    let videoId = null;
    const match = url.match(/^.*(youtu.be\/|v\/|u\/\w\/|embed\/|watch\?v=|&v=)([^#&?]*).*/);
    if (match && match[2].length === 11) videoId = match[2];
    if (!videoId) return { success: false };

    let data = { title: '', description: '', transcript: '' };
    try {
        const pageRes = await axios.get(`https://www.youtube.com/watch?v=${videoId}`, {
            headers: { 'User-Agent': 'Mozilla/5.0' },
            timeout: 30000
        });
        const $ = cheerio.load(pageRes.data);
        data.title = $('meta[name="title"]').attr('content') || $('title').text();
        data.description = ($('meta[name="description"]').attr('content') || '');
        
        const transcriptObj = await YoutubeTranscript.fetchTranscript(videoId).catch(() => []);
        if (transcriptObj && transcriptObj.length > 0) {
            data.transcript = transcriptObj.map(t => t.text).join(' ');
        }
        return { success: true, ...data };
    } catch (e) {
        return { success: false };
    }
}

async function getWebsiteContent(url) {
    if (!await isSafeUrl(url)) return null;
    try {
        const response = await axios.get(url, {
            headers: { 'User-Agent': 'DardcorBot/1.0' },
            timeout: 60000,
            maxContentLength: Infinity,
            maxBodyLength: Infinity
        });
        const $ = cheerio.load(response.data);
        $('script, style, nav, footer, header, svg, img, iframe, noscript, link, meta, video, audio, aside, form').remove();
        return $('body').text().replace(/\s+/g, ' ').trim();
    } catch (e) {
        return null;
    }
}

async function searchWeb(query) {
    if (!query || typeof query !== 'string') return null;
    const q = query;

    if (process.env.GOOGLE_API_KEY && process.env.GOOGLE_CX) {
        try {
            const res = await axios.get('https://www.googleapis.com/customsearch/v1', {
                params: { key: process.env.GOOGLE_API_KEY, cx: process.env.GOOGLE_CX, q: q, num: 10 },
                timeout: 30000
            });
            if (res.data && res.data.items && res.data.items.length > 0) {
                return res.data.items.map(r => `## [${(r.title || '')}](${(r.link || '')})\n${(r.snippet || '')}`).join('\n\n');
            }
        } catch (e) {
            await sendDiscordError("Google Search API Error", e);
        }
    }

    try {
        const res = await axios.get(`https://ddg-api.herokuapp.com/search?q=${encodeURIComponent(q)}&limit=10`, { timeout: 30000 });
        if (res.data && Array.isArray(res.data) && res.data.length > 0) {
            return res.data.map(r => `## [${(r.title || '')}](${(r.link || '')})\n${(r.snippet || '')}`).join('\n\n');
        }
        return null;
    } catch (e) {
        return null;
    }
}

router.get('/', (req, res) => handleLoginCheck(req, res, 'index'));
router.get('/dardcor', (req, res) => handleLoginCheck(req, res, 'dardcor'));
router.get('/register', (req, res) => handleLoginCheck(req, res, 'register'));
router.get('/loading', (req, res) => res.render('loading'));

router.get('/verify-otp', (req, res) => {
    if (req.session.userAccount) return res.redirect('/loading');
    res.render('verify', { email: req.query.email || '' });
});

router.get('/auth/google', async (req, res) => {
    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    const host = req.get('host');
    const referer = req.get('Referer') || '';
    let targetPath = '/register';
    if (referer.includes('/dardcor')) targetPath = '/dardcor';
    const fullUrl = `${protocol}://${host}${targetPath}`;
    
    const { data, error } = await supabase.auth.signInWithOAuth({
        provider: 'google',
        options: { redirectTo: fullUrl, queryParams: { access_type: 'offline', prompt: 'select_account' } }
    });
    if (error) return res.redirect(`${targetPath}?error=` + encodeURIComponent(error.message));
    res.redirect(data.url);
});

router.post('/auth/google-bridge', async (req, res) => {
    const { accessToken } = req.body;
    if (!accessToken) return res.status(400).json({ success: false, message: 'Invalid payload' });
    try {
        const { data: { user }, error } = await supabase.auth.getUser(accessToken);
        if (error || !user) throw new Error('Authorization expired');
        let { data: dbUser } = await supabase.from('dardcor_users').select('*').eq('email', user.email).maybeSingle();
        if (!dbUser) {
            const { data: newUser, error: insErr } = await supabase.from('dardcor_users').insert([{
                id: user.id,
                email: user.email,
                username: user.user_metadata.full_name || user.user_metadata.name || user.email.split('@')[0],
                password: await bcrypt.hash(uuidv4() + STATIC_KEY + user.id, 12),
                profile_image: user.user_metadata.avatar_url || user.user_metadata.picture
            }]).select().single();
            if (insErr) throw insErr;
            dbUser = newUser;
        }
        req.session.userAccount = dbUser;
        req.session.cookie.maxAge = SESSION_DURATION;
        res.cookie('dardcor_perm_auth', generateAuthToken(dbUser), cookieConfig);
        req.session.save((err) => {
            if (err) throw err;
            res.json({ success: true, redirectUrl: '/loading' });
        });
    } catch (e) {
        await sendDiscordError("OAuth Bridge Failure", e);
        res.status(500).json({ success: false, message: e.message });
    }
});

router.post('/dardcor-login', authLimiter, async (req, res) => {
    let { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Incomplete credentials.' });
    try {
        const { data: user, error } = await supabase.from('dardcor_users').select('*').eq('email', email.trim().toLowerCase()).maybeSingle();
        if (error || !user) return res.status(401).json({ success: false, message: 'Authentication failed.' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ success: false, message: 'Authentication failed.' });
        req.session.userAccount = user;
        req.session.cookie.maxAge = SESSION_DURATION;
        res.cookie('dardcor_perm_auth', generateAuthToken(user), cookieConfig);
        req.session.save((err) => {
            if (err) throw err;
            res.status(200).json({ success: true, redirectUrl: '/loading' });
        });
    } catch (err) {
        await sendDiscordError("Login System", err);
        res.status(500).json({ success: false, message: 'Internal engine error.' });
    }
});

router.get('/dardcor-logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('dardcor_perm_auth');
        res.redirect('/dardcor');
    });
});

router.post('/register', authLimiter, async (req, res) => {
    let { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ success: false, message: 'All fields are mandatory.' });
    email = email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ success: false, message: 'Invalid email syntax.' });
    try {
        const { data: existingUser } = await supabase.from('dardcor_users').select('email').eq('email', email).maybeSingle();
        if (existingUser) return res.status(409).json({ success: false, message: 'Identity already exists.' });
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const hashedPassword = await bcrypt.hash(password, 12);
        await supabase.from('verification_codes').delete().eq('email', email);
        const { error: dbErr } = await supabase.from('verification_codes').insert([{
            username: username.substring(0, 100),
            email,
            password: hashedPassword,
            otp
        }]);
        if (dbErr) throw dbErr;
        await transporter.sendMail({
            from: `"Dardcor AI Security" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Verification Code - Dardcor AI',
            html: `
                <div style="background-color:#050508; color:#ffffff; font-family:sans-serif; padding:40px; text-align:center; border:1px solid #333; border-radius:10px; max-width:500px; margin:auto;">
                    <h2 style="color:#a855f7;">Verification Required</h2>
                    <p style="color:#ccc;">Your secure handshake code is:</p>
                    <div style="background:#1e1e1e; padding:20px; font-size:32px; letter-spacing:10px; font-weight:bold; color:#fff; border-radius:8px; margin:20px 0;">${otp}</div>
                    <p style="font-size:12px; color:#666;">Expires in 5 minutes.</p>
                </div>
            `
        });
        res.status(200).json({ success: true, email: email, redirectUrl: `/verify-otp?email=${encodeURIComponent(email)}` });
    } catch (err) {
        await sendDiscordError("Auth Flow", err);
        res.status(500).json({ success: false, message: "System failure." });
    }
});

router.post('/verify-otp', authLimiter, async (req, res) => {
    try {
        const { email, otp } = req.body;
        if (!email || !otp) return res.status(400).json({ success: false, message: "Invalid request." });
        const { data: record, error: fetchErr } = await supabase.from('verification_codes').select('*').eq('email', email).eq('otp', otp).maybeSingle();
        if (fetchErr || !record) return res.status(400).json({ success: false, message: 'Invalid code.' });
        const { data: newUser, error: insErr } = await supabase.from('dardcor_users').insert([{
            username: record.username,
            email: record.email,
            password: record.password
        }]).select().single();
        if (insErr) throw insErr;
        await supabase.from('verification_codes').delete().eq('email', email);
        req.session.userAccount = newUser;
        req.session.cookie.maxAge = SESSION_DURATION;
        res.cookie('dardcor_perm_auth', generateAuthToken(newUser), cookieConfig);
        req.session.save((err) => {
            if (err) throw err;
            res.status(200).json({ success: true, redirectUrl: '/loading' });
        });
    } catch (err) {
        await sendDiscordError("OTP Fault", err);
        res.status(500).json({ success: false, message: "Verification failed." });
    }
});

router.get('/dardcorchat/profile', protectedRoute, async (req, res) => {
    try {
        const { data: user } = await supabase.from('dardcor_users').select('*').eq('id', req.session.userAccount.id).single();
        res.render('dardcorchat/profile', { user: user || req.session.userAccount, success: req.query.success, error: req.query.error });
    } catch (e) {
        res.redirect('/dardcor');
    }
});

router.post('/dardcor/profile/update', protectedRoute, upload.single('profile_image'), async (req, res) => {
    const userId = req.session.userAccount.id;
    let updates = {
        username: req.body.username ? req.body.username.substring(0, 100) : req.session.userAccount.username
    };
    try {
        if (req.body.password && req.body.password.trim() !== "") {
            if (req.body.password !== req.body.confirm_password) return res.redirect('/dardcorchat/profile?error=Password mismatch');
            updates.password = await bcrypt.hash(req.body.password.trim(), 12);
        }
        if (req.file) {
            const fileBuffer = fs.readFileSync(req.file.path);
            const fileExt = path.extname(req.file.originalname).toLowerCase();
            const fileName = `avatar-${userId}-${Date.now()}${fileExt}`;
            const { error: uploadErr } = await supabase.storage.from('avatars').upload(fileName, fileBuffer, {
                contentType: req.file.mimetype,
                upsert: true
            });
            if (uploadErr) throw uploadErr;
            const { data: publicUrlData } = supabase.storage.from('avatars').getPublicUrl(fileName);
            updates.profile_image = publicUrlData.publicUrl;
            fs.unlink(req.file.path, () => {});
        }
        const { data, error } = await supabase.from('dardcor_users').update(updates).eq('id', userId).select().single();
        if (error) throw error;
        req.session.userAccount = data;
        res.cookie('dardcor_perm_auth', generateAuthToken(data), cookieConfig);
        req.session.save(() => {
            res.redirect('/dardcorchat/profile?success=Profile updated.');
        });
    } catch (err) {
        if (req.file && req.file.path) fs.unlink(req.file.path, () => {});
        res.redirect('/dardcorchat/profile?error=Update error: ' + encodeURIComponent(err.message));
    }
});

router.get('/dardcorchat/dardcor-ai', protectedRoute, (req, res) => {
    res.redirect(`/dardcorchat/dardcor-ai/${uuidv4()}`);
});

router.get('/dardcorchat/dardcor-ai/preview/:id', protectedRoute, async (req, res) => {
    if (!uuidValidate(req.params.id)) return res.status(404).send('Invalid');
    try {
        const { data, error } = await supabase.from('previews_website').select('code').eq('id', req.params.id).maybeSingle();
        if (error || !data) return res.status(404).send('Not Found');
        
        res.removeHeader('X-Frame-Options');
        res.setHeader('Content-Security-Policy', "default-src 'self' 'unsafe-inline' 'unsafe-eval' https: data: blob:; img-src 'self' https: data: blob:; font-src 'self' https: data:; connect-src 'self' https:;");
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('X-XSS-Protection', '0');
        res.send(data.code);
    } catch (err) {
        res.status(500).send("Error");
    }
});

router.get('/dardcorchat/dardcor-ai/diagram/:id', protectedRoute, async (req, res) => {
    if (!uuidValidate(req.params.id)) return res.status(404).send('Invalid');
    try {
        const { data, error } = await supabase.from('previews_website').select('code').eq('id', req.params.id).maybeSingle();
        if (error || !data) return res.status(404).send('Not Found');
        const codeBase64 = Buffer.from(data.code).toString('base64');
        res.removeHeader('X-Frame-Options');
        res.render('dardcorchat/diagram', { code: codeBase64 });
    } catch (err) {
        res.status(500).send("Error");
    }
});

router.get('/dardcorchat/dardcor-ai/:conversationId', protectedRoute, async (req, res) => {
    const userId = req.session.userAccount.id;
    let requestedId = req.params.conversationId;

    if (!uuidValidate(requestedId)) {
        return res.redirect(`/dardcorchat/dardcor-ai/${uuidv4()}`);
    }

    try {
        const { data: conversationList } = await supabase
            .from('conversations')
            .select('*')
            .eq('user_id', userId)
            .not('title', 'is', null)
            .order('updated_at', { ascending: false });

        const { data: activeChatHistory } = await supabase
            .from('history_chat')
            .select('*')
            .eq('conversation_id', requestedId)
            .eq('user_id', userId)
            .order('created_at', { ascending: true });
        
        if (activeChatHistory && activeChatHistory.length > 0) {
            await Promise.all(activeChatHistory.map(async (msg) => {
                if (msg.file_metadata && Array.isArray(msg.file_metadata)) {
                    msg.file_metadata = await Promise.all(msg.file_metadata.map(async (file) => {
                        if (file.storage_path) {
                            try {
                                const { data: signed } = await supabase.storage.from('chat-attachments').createSignedUrl(file.storage_path, 3600);
                                if (signed) file.url = signed.signedUrl;
                            } catch (e) {}
                        }
                        return file;
                    }));
                }
            }));
        }

        req.session.currentConversationId = requestedId;
        res.render('dardcorchat/layout', {
            user: req.session.userAccount,
            chatHistory: activeChatHistory || [],
            conversationList: conversationList || [],
            activeConversationId: requestedId,
            contentPage: 'dardcorai'
        });
    } catch (err) {
        res.redirect('/dardcor');
    }
});

router.get('/api/chat/:conversationId', protectedRoute, apiLimiter, async (req, res) => {
    const userId = req.session.userAccount.id;
    const convoId = req.params.conversationId;
    
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    
    if (!uuidValidate(convoId)) return res.status(404).json({ success: false, error: 'Invalid ID' });

    try {
        const { data: conversationExists } = await supabase.from('conversations').select('id').eq('id', convoId).eq('user_id', userId).maybeSingle();
        
        const { data: history, error } = await supabase.from('history_chat').select('*').eq('conversation_id', convoId).eq('user_id', userId).order('created_at', { ascending: true });
        
        if (error) throw error;

        if (!conversationExists && (!history || history.length === 0)) {
            return res.status(200).json({ success: true, history: [] });
        }

        const safeHistory = history ? history.map(msg => ({
            ...msg,
            message: msg.message || "",
            file_metadata: Array.isArray(msg.file_metadata) ? msg.file_metadata : []
        })) : [];

        if (safeHistory.length > 0) {
            await Promise.all(safeHistory.map(async (msg) => {
                if (msg.file_metadata.length > 0) {
                    msg.file_metadata = await Promise.all(msg.file_metadata.map(async (file) => {
                        if (file.storage_path) {
                            try {
                                const { data: signed } = await supabase.storage.from('chat-attachments').createSignedUrl(file.storage_path, 3600);
                                if (signed) file.url = signed.signedUrl;
                            } catch (e) {}
                        }
                        return file;
                    }));
                }
            }));
        }
        req.session.currentConversationId = convoId;
        res.json({ success: true, history: safeHistory });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

router.post('/dardcorchat/ai/new-chat', protectedRoute, (req, res) => {
    const newId = uuidv4();
    req.session.currentConversationId = newId;
    req.session.save(() => {
        res.json({ success: true, redirectUrl: `/dardcorchat/dardcor-ai/${newId}` });
    });
});

router.post('/dardcorchat/ai/rename-chat', protectedRoute, async (req, res) => {
    const { conversationId, newTitle } = req.body;
    if (!uuidValidate(conversationId) || !newTitle) return res.status(400).json({ success: false });
    try {
        const { error } = await supabase.from('conversations').update({
            title: newTitle.substring(0, 150),
            updated_at: new Date()
        }).eq('id', conversationId).eq('user_id', req.session.userAccount.id);
        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

router.post('/dardcorchat/ai/delete-chat-history', protectedRoute, async (req, res) => {
    const { conversationId } = req.body;
    if (!uuidValidate(conversationId)) return res.status(400).json({ success: false });
    try {
        await supabase.from('history_chat').delete().eq('conversation_id', conversationId).eq('user_id', req.session.userAccount.id);
        await supabase.from('conversations').delete().eq('id', conversationId).eq('user_id', req.session.userAccount.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

router.get('/api/project/files', protectedRoute, async (req, res) => {
    try {
        const { data, error } = await supabase.from('project_files').select('*').eq('user_id', req.session.userAccount.id).order('is_folder', { ascending: false }).order('name', { ascending: true });
        if (error) throw error;
        res.json({ success: true, files: data || [] });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

router.post('/api/project/save', protectedRoute, async (req, res) => {
    const { name, path: filePath, content, language, is_folder } = req.body;
    if (!name) return res.status(400).json({ success: false });
    try {
        const { error } = await supabase.from('project_files').upsert({
            user_id: req.session.userAccount.id,
            name: name.substring(0, 255),
            path: filePath || 'root',
            content: content || '',
            language: language || 'plaintext',
            is_folder: !!is_folder,
            updated_at: new Date()
        }, { onConflict: 'user_id, path, name' });
        if (error) throw error;
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

router.post('/api/project/delete', protectedRoute, async (req, res) => {
    const { name, path: filePath } = req.body;
    try {
        const { error } = await supabase.from('project_files').delete().match({
            user_id: req.session.userAccount.id,
            name,
            path: filePath || 'root'
        });
        if (error) throw error;
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

router.post('/dardcorchat/ai/store-preview', protectedRoute, async (req, res) => {
    const previewId = uuidv4();
    const { code, type } = req.body;
    try {
        const { error } = await supabase.from('previews_website').insert({
            id: previewId,
            user_id: req.session.userAccount.id,
            code,
            type: type || 'website'
        });
        if (error) throw error;
        res.json({ success: true, previewId });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

router.post('/dardcorchat/ai/chat-stream', protectedRoute, uploadMiddleware, async (req, res) => {
    req.socket.setTimeout(0);
    req.setTimeout(0);
    
    const userId = req.session.userAccount.id;
    let { message, conversationId, useWebSearch, isImageGeneration } = req.body;
    const uploadedFiles = req.files || [];
    
    if (!uuidValidate(conversationId)) conversationId = uuidv4();
    
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    if (res.flushHeaders) res.flushHeaders();

    if (res.writableEnded) return;
    res.write(`event: message\ndata: ${JSON.stringify({ chunk: "" })}\n\n`);
    if (res.flush) res.flush();

    let botMessageId = null;
    let fullResponse = "";
    let isStreamCompleted = false;

    const cleanupFiles = () => {
        uploadedFiles.forEach(file => {
            if (file.path && fs.existsSync(file.path)) fs.unlink(file.path, () => {});
        });
    };

    req.on('close', async () => {
        if (!isStreamCompleted && botMessageId && fullResponse.length > 0) {
             let finalMsg = fullResponse;
             finalMsg = finalMsg.replace(/\u0000/g, '');
             try { await supabase.from('history_chat').update({ message: finalMsg }).eq('id', botMessageId); } catch(e) {}
        }
        cleanupFiles();
    });

    try {
        const { data: convExists } = await supabase.from('conversations').select('id').eq('id', conversationId).maybeSingle();
        if (!convExists) {
            await supabase.from('conversations').insert({
                id: conversationId,
                user_id: userId,
                title: message.substring(0, 80).replace(/\n/g, ' ') || "New Conversation"
            });
        } else {
            await supabase.from('conversations').update({ updated_at: new Date() }).eq('id', conversationId);
        }

        const fileMetadata = [];
        const filePromises = uploadedFiles.map(async (file) => {
             const fileBuffer = await fsPromises.readFile(file.path);
             const fileExt = path.extname(file.originalname).toLowerCase();
             const storagePath = `${userId}/${Date.now()}-${uuidv4()}${fileExt}`;
             const meta = { filename: file.originalname, size: file.size, mimetype: file.mimetype, storage_path: storagePath };
             
             try {
                const { error: uploadErr } = await supabase.storage.from('chat-attachments').upload(storagePath, fileBuffer, {
                    contentType: file.mimetype,
                    upsert: false
                });
                if (!uploadErr) {
                    const { data: signed } = await supabase.storage.from('chat-attachments').createSignedUrl(storagePath, 3600);
                    if (signed) meta.url = signed.signedUrl;
                }
             } catch(e) {}
             return { meta, buffer: fileBuffer, file };
        });

        const processedFiles = await Promise.all(filePromises);
        processedFiles.forEach(pf => fileMetadata.push(pf.meta));

        await supabase.from('history_chat').insert({
            user_id: userId,
            conversation_id: conversationId,
            role: 'user',
            message: message,
            file_metadata: fileMetadata,
            embedding: null
        });

        const { data: botMsg } = await supabase.from('history_chat').insert({
            user_id: userId,
            conversation_id: conversationId,
            role: 'bot',
            message: '',
            embedding: null
        }).select('id').single();
        botMessageId = botMsg.id;

        const contextData = { 
            searchResults: '', 
            globalHistory: '', 
            isImageGeneration: isImageGeneration === 'true',
            username: req.session.userAccount.username 
        };
        
        let systemContext = "";
        const geminiFiles = [];
        let fileTextContext = "";
        let visualFilesInfo = "";
        
        const hasFiles = uploadedFiles.length > 0;
        const hasWebSearch = useWebSearch === 'true' || message.toLowerCase().match(/(cari|search|berita|info|terbaru|siapa|apa|kapan|dimana|bagaimana|mengapa|tutorial|harga|saham|politik|cuaca)/);
        const hasUrl = message.match(/(https?:\/\/[^\s]+)/g);

        if (hasFiles || hasWebSearch || hasUrl) {
            const searchPromise = (async () => {
                 if (hasWebSearch) {
                    return await searchWeb(message);
                 }
                 return null;
            })();

            const urls = hasUrl || [];
            const urlPromises = urls.map(async (url) => {
                try {
                    if (url.includes('youtube.com') || url.includes('youtu.be')) {
                        const yt = await getYouTubeData(url);
                        if (yt.success) return `\n[YOUTUBE: ${yt.title}]\n${yt.description}\n${yt.transcript}\n`;
                    } else {
                        const web = await getWebsiteContent(url);
                        if (web) return `\n[WEB: ${url}]\n${web}\n`;
                    }
                } catch (e) {}
                return '';
            });

            const textExtractionPromises = processedFiles.map(async ({ file, buffer }) => {
                const isVisual = file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/') || file.mimetype.startsWith('audio/');
                
                if (isVisual) {
                    geminiFiles.push({ ...file, buffer: buffer });
                    visualFilesInfo += `\n[VISUAL/MEDIA ATTACHMENT]: ${file.originalname} (See inline data)`;
                } else if (file.mimetype === 'application/pdf') {
                    geminiFiles.push({ ...file, buffer: buffer });
                    try {
                         const pdfText = await parsePdfSafe(buffer);
                         fileTextContext += `\n[PDF: ${file.originalname}]\n${pdfText}\n`;
                    } catch(e) {
                         fileTextContext += `\n[PDF: ${file.originalname}] (Text extraction failed, relying on vision)\n`;
                    }
                } else {
                    try {
                        if (file.mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
                            const doc = await mammoth.extractRawText({ buffer: buffer });
                            fileTextContext += `\n[DOCX: ${file.originalname}]\n${doc.value}\n`;
                        } else if (file.mimetype.includes('spreadsheet') || file.mimetype.includes('excel') || file.mimetype.includes('csv')) {
                            const wb = xlsx.read(buffer, { type: 'buffer' });
                            wb.SheetNames.forEach(n => {
                                const csv = xlsx.utils.sheet_to_csv(wb.Sheets[n]);
                                fileTextContext += `\n[SHEET: ${n}]\n${csv}\n`;
                            });
                        } else {
                            fileTextContext += `\n[FILE: ${file.originalname}]\n${buffer.toString('utf-8')}\n`;
                        }
                    } catch (fileErr) {
                        fileTextContext += `\n[ERROR READING FILE: ${file.originalname}] (Considered as binary/visual)\n`;
                        geminiFiles.push({ ...file, buffer: buffer });
                    }
                }
            });

            await Promise.all([searchPromise.then(res => contextData.searchResults = res), ...urlPromises.map(p => p.then(res => systemContext += res)), ...textExtractionPromises]);
        }

        if (fileTextContext) systemContext += `\n[CONTEXT FILES TEXT]\n${fileTextContext}\n`;
        if (visualFilesInfo) systemContext += `\n[ATTACHMENTS]\n${visualFilesInfo}\n`;

        const { data: historyData } = await supabase.from('history_chat').select('role, message').eq('conversation_id', conversationId).order('created_at', { ascending: true });

        const refinedPrompt = systemContext ? `${systemContext}\n\nUser Query: ${message}` : message;
        const stream = await handleChatStream(refinedPrompt, geminiFiles, historyData, contextData);

        let updateCounter = 0;
        let lastUpdateTime = Date.now();

        for await (const chunk of stream) {
            if (res.writableEnded) break;
            const chunkText = chunk.text();
            const safeChunk = chunkText.replace(/\u0000/g, '');
            fullResponse += safeChunk;
            res.write(`event: message\ndata: ${JSON.stringify({ chunk: safeChunk })}\n\n`);
            if (res.flush) res.flush();
            
            updateCounter++;
            const now = Date.now();
            if (updateCounter > 50 || (now - lastUpdateTime > 1500)) {
                await supabase.from('history_chat').update({ message: fullResponse }).eq('id', botMessageId);
                updateCounter = 0;
                lastUpdateTime = now;
            }
        }

        isStreamCompleted = true;
        if (!fullResponse) fullResponse = "[No content generated]";
        fullResponse = fullResponse.replace(/\u0000/g, '');
        fullResponse = fullResponse.replace(/<think>[\s\S]*?<\/think>/gi, '').replace(/<think>/gi, '').replace(/<\/think>/gi, '').trim();
        
        await supabase.from('history_chat').update({ message: fullResponse }).eq('id', botMessageId);
        
        if (!res.writableEnded) {
            res.write(`event: message\ndata: ${JSON.stringify({ done: true })}\n\n`);
            res.end();
        }

    } catch (error) {
        await sendDiscordError("Stream Error", error);
        const errorMsg = "Maaf, saya mengalami kendala saat memproses permintaan Anda.";
        if (botMessageId) {
            await supabase.from('history_chat').update({ message: fullResponse + "\n\n[SYSTEM ERROR]" }).eq('id', botMessageId);
            if (!res.writableEnded) {
                res.write(`event: message\ndata: ${JSON.stringify({ chunk: errorMsg })}\n\n`);
            }
        }
        if (!res.writableEnded) {
            res.write(`event: message\ndata: ${JSON.stringify({ done: true })}\n\n`);
            res.end();
        }
    } finally {
        cleanupFiles();
    }
});

module.exports = router;
