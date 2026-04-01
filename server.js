require('dotenv').config();
const bcrypt = require('bcrypt');
const express = require('express');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const multer = require('multer');
const rateLimit = require('express-rate-limit'); // Защита от брутфорса

const app = express();
const PORT = process.env.PORT || 3000;

// --- 1. ПУТИ И БАЗА ---
const DB_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DB_DIR, 'users.json');
const UPLOAD_DIR = path.join(__dirname, 'public/uploads');

if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR);
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify([]));

// --- 2. ЗАЩИТА (RATE LIMITING) ---
// Ограничение: максимум 100 запросов в 15 минут с одного IP для общего API
const generalLimit = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, message: "Слишком много запросов. Попробуйте позже." }
});

// Жесткое ограничение для авторизации (защита от перебора паролей)
const authLimit = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10, // 10 попыток на 15 минут
    message: { success: false, message: "Слишком много попыток входа. Подождите 15 минут." }
});

// --- 3. КОНФИГ ЗАГРУЗКИ ФАЙЛОВ ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'vortex_' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, 
    fileFilter: (req, file, cb) => {
        const allowed = ['.jpg', '.jpeg', '.png', '.jar', '.zip'];
        if (allowed.includes(path.extname(file.originalname).toLowerCase())) cb(null, true);
        else cb(new Error('Invalid format'));
    }
});

// --- 4. MIDDLEWARE ---
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.use('/api/', generalLimit); // Применяем общий лимит на все API

app.use(session({
    store: new FileStore({ path: './sessions', logFn: () => {} }),
    secret: 'vortex_secret_key_@neobutinka_99', 
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }
}));

// Хелперы
const decodePass = (p) => Buffer.from(p, 'base64').toString('utf8');
const getUsers = () => JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
const saveUsers = (users) => fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

// --- 5. API ---

// РЕГИСТРАЦИЯ (С ВАЛИДАЦИЕЙ)
app.post('/api/register', authLimit, async (req, res) => {
    try {
        let { username, email, password } = req.body;
        
        // Пункт 4: Валидация на стороне сервера
        if (!username || username.length < 3 || username.length > 20) return res.json({ success: false, message: 'Неверная длина логина' });
        if (!email.includes('@')) return res.json({ success: false, message: 'Неверный формат почты' });

        password = decodePass(password);
        let users = getUsers();

        if (users.find(u => u.username === username)) return res.json({ success: false, message: 'Логин занят' });
        if (users.find(u => u.email === email)) return res.json({ success: false, message: 'Почта занята' });

        const hashedPassword = await bcrypt.hash(password, 10);
        users.push({
            uid: Math.floor(10000 + Math.random() * 90000),
            username, email, password: hashedPassword,
            reg_date: new Date().toLocaleDateString('ru-RU'),
            sub_days: 0, recovery: { code: null, expires: null }
        });

        saveUsers(users);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false }); }
});

// ВХОД
app.post('/api/login', authLimit, async (req, res) => {
    try {
        let { username, password } = req.body;
        password = decodePass(password);

        const users = getUsers();
        const user = users.find(u => u.username === username || u.email === username);

        if (user && await bcrypt.compare(password, user.password)) {
            const { password: _, recovery: __, ...safeUser } = user;
            req.session.user = safeUser;
            res.json({ success: true, user: safeUser });
        } else {
            res.json({ success: false, message: 'Доступ запрещен' });
        }
    } catch (e) { res.status(500).json({ success: false }); }
});

// ЗАБЫЛИ ПАРОЛЬ (Генерация кода с TTL)
app.post('/api/forget', authLimit, async (req, res) => {
    const { email } = req.body;
    let users = getUsers();
    const user = users.find(u => u.email === email || u.username === email);
    
    if (!user) return res.json({ success: false, message: 'Пользователь не найден' });

    const code = Math.floor(100000 + Math.random() * 900000);
    // Пункт 2: Добавляем срок жизни кода (10 минут)
    user.recovery = { 
        code: code, 
        expires: Date.now() + (10 * 60 * 1000) 
    };
    saveUsers(users);

    try {
        await transporter.sendMail({
            from: `"Vortex Support" <${process.env.EMAIL_USER}>`,
            to: user.email,
            subject: 'Vortex Code',
            html: `<b>Code: ${code}</b> (Valid for 10 min)`
        });
        res.json({ success: true });
    } catch (e) { res.json({ success: false, message: 'Mail error' }); }
});

// СБРОС ПАРОЛЯ (Защита от IDOR и устаревших кодов)
app.post('/api/reset-password', authLimit, async (req, res) => {
    try {
        let { email, code, newPassword } = req.body;
        newPassword = decodePass(newPassword);

        let users = getUsers();
        const user = users.find(u => u.email === email || u.username === email);

        if (!user || !user.recovery.code) return res.json({ success: false, message: 'Запрос не найден' });

        // Проверка времени жизни кода
        if (Date.now() > user.recovery.expires) {
            user.recovery = { code: null, expires: null };
            saveUsers(users);
            return res.json({ success: false, message: 'Код устарел' });
        }

        if (Number(user.recovery.code) === Number(code)) {
            user.password = await bcrypt.hash(newPassword, 10);
            user.recovery = { code: null, expires: null }; // Чистим код после успеха
            saveUsers(users);
            res.json({ success: true });
        } else {
            res.json({ success: false, message: 'Неверный код' });
        }
    } catch (e) { res.status(500).json({ success: false }); }
});

// ЗАГРУЗКА ФАЙЛА (Только для авторизованных)
app.post('/api/upload', (req, res) => {
    if (!req.session.user) return res.status(401).json({ success: false });
    upload.single('vortex_file')(req, res, (err) => {
        if (err) return res.json({ success: false, message: err.message });
        res.json({ success: true, fileName: req.file.filename });
    });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// ЗАПУСК
app.listen(PORT, () => {
    console.clear();
    console.log(`\x1b[34m
    __      ______  _____ _______ ________   __
    \\ \\    / / __ \\|  __ \\__   __|  ____\\ \\ / /
     \\ \\  / / |  | | |__) | | |  | |__   \\  / / 
      \\ \\/ /| |  | |  _  /  | |  |  __|   > <  
       \\  / | |__| | | \\ \\  | |  | |____ /  \\ \\ 
        \\/   \\____/|_|  \\_\\ |_|  |______/_/   \\_\\
    \x1b[0m`);
    console.log(`\x1b[32m >> Project:   VORTEX\x1b[0m`);
    console.log(`\x1b[32m >> Developer: @neobutinka\x1b[0m`);
    console.log(`\x1b[32m >> Status:    ONLINE [http://localhost:${PORT}]\x1b[0m`);
    console.log(`\x1b[33m >> Shields:   RATE_LIMITER ACTIVE | IDOR_PROTECTION ON\x1b[0m`);
    console.log(`-----------------------------------------------------------`);
});