import express from 'express';
import cors from 'cors';
import multer from 'multer';
import sqlite3 from 'sqlite3';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import session from 'express-session';
import bcrypt from 'bcrypt';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

app.use(session({
    secret: 'snapquest_final_secret_2024',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: 'lax' }
}));

if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
const db = new sqlite3.Database('snapquest.db');

db.serialize(() => {
    // Tables existantes
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        full_name TEXT,
        role TEXT DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS photos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        image_url TEXT,
        caption TEXT,
        user_id INTEGER,
        user_name TEXT,
        created_date DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // NOUVELLES TABLES : J'aime et Commentaires
    db.run(`CREATE TABLE IF NOT EXISTS likes (
        user_id INTEGER,
        photo_id INTEGER,
        PRIMARY KEY (user_id, photo_id)
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        photo_id INTEGER,
        user_id INTEGER,
        user_name TEXT,
        text TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    const adminHash = bcrypt.hashSync('darkmods007', 10);
    db.run(`INSERT OR REPLACE INTO users (id, username, password, full_name, role) 
            VALUES (1, 'DarkMods', ?, 'DarkMods Nemesis 007', 'admin')`, [adminHash]);
    
    console.log('✅ Base de données prête avec le système de J\\'aime et Commentaires');
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => {
        const unique = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, unique);
    }
});
const upload = multer({ storage });

const isAuthenticated = (req, res, next) => {
    if (req.session.userId) return next();
    res.status(401).json({ error: 'Non authentifié' });
};

const isAdmin = (req, res, next) => {
    if (req.session.role === 'admin') return next();
    res.status(403).json({ error: 'Admin requis' });
};

// ============ ROUTES AUTH & UTILISATEURS ============

app.post('/api/auth/register', async (req, res) => {
    const { username, password, full_name } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Champs requis' });
    
    db.get('SELECT COUNT(*) as count FROM users WHERE username != "DarkMods"', (err, result) => {
        const role = result.count === 0 ? 'moderator' : 'user';
        const hash = bcrypt.hashSync(password, 10);
        db.run('INSERT INTO users (username, password, full_name, role) VALUES (?, ?, ?, ?)', 
            [username, hash, full_name || username, role], 
            function(err) {
                if (err) return res.status(400).json({ error: 'Nom d\\'utilisateur déjà pris' });
                req.session.userId = this.lastID;
                req.session.role = role;
                res.json({ user: { id: this.lastID, username, full_name: full_name || username, role } });
            });
    });
});

app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err || !user) return res.status(401).json({ error: 'Identifiants invalides' });
        
        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: 'Identifiants invalides' });
        }
        
        let finalRole = user.role;
        if (user.username === 'DarkMods') {
            finalRole = 'admin';
            db.run('UPDATE users SET role = ? WHERE id = ?', ['admin', user.id]);
        }
        
        req.session.userId = user.id;
        req.session.role = finalRole;
        res.json({ user: { id: user.id, username: user.username, full_name: user.full_name, role: finalRole } });
    });
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/me', (req, res) => {
    if (!req.session.userId) return res.json(null);
    db.get('SELECT id, username, full_name, role FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        if (err || !user) return res.json(null);
        if (user.username === 'DarkMods') user.role = 'admin';
        res.json(user);
    });
});

app.get('/api/users', isAdmin, (req, res) => {
    db.all('SELECT id, username, full_name, role, created_at FROM users', (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

app.put('/api/users/:id/role', isAdmin, (req, res) => {
    const { id } = req.params;
    const { role } = req.body;
    db.get('SELECT username FROM users WHERE id = ?', [id], (err, user) => {
        if (user && user.username === 'DarkMods') return res.status(403).json({ error: 'Intouchable' });
        db.run('UPDATE users SET role = ? WHERE id = ?', [role, id], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Rôle mis à jour' });
        });
    });
});

// ============ ROUTES PHOTOS, LIKES & COMMENTAIRES ============

app.get('/api/photos', isAuthenticated, (req, res) => {
    const currentUserId = req.session.userId;
    
    // Récupérer les photos, puis les likes, puis les commentaires pour tout assembler
    db.all('SELECT * FROM photos ORDER BY created_date DESC', [], (err, photos) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!photos || photos.length === 0) return res.json([]);
        
        db.all('SELECT * FROM likes', [], (err, allLikes) => {
            db.all('SELECT * FROM comments ORDER BY created_at ASC', [], (err, allComments) => {
                
                const photosWithDetails = photos.map(photo => {
                    const photoLikes = allLikes.filter(l => l.photo_id === photo.id);
                    const photoComments = allComments.filter(c => c.photo_id === photo.id);
                    
                    return {
                        ...photo,
                        likesCount: photoLikes.length,
                        isLikedByMe: photoLikes.some(l => l.user_id === currentUserId),
                        comments: photoComments
                    };
                });
                
                res.json(photosWithDetails);
            });
        });
    });
});

app.post('/api/photos', isAuthenticated, upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Image requise' });
    const image_url = `/uploads/${req.file.filename}`;
    db.get('SELECT full_name FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        const userName = user ? user.full_name : 'Anonyme';
        db.run(
            'INSERT INTO photos (image_url, caption, user_id, user_name) VALUES (?, ?, ?, ?)',
            [image_url, req.body.caption || '', req.session.userId, userName],
            function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ id: this.lastID, image_url, caption: req.body.caption, user_name: userName });
            }
        );
    });
});

app.delete('/api/photos/:id', isAuthenticated, (req, res) => {
    const { id } = req.params;
    const isModOrAdmin = req.session.role === 'admin' || req.session.role === 'moderator';
    const query = isModOrAdmin ? 'DELETE FROM photos WHERE id = ?' : 'DELETE FROM photos WHERE id = ? AND user_id = ?';
    const params = isModOrAdmin ? [id] : [id, req.session.userId];
    
    db.run(query, params, function(err) {
        if (err) return res.status(500).json({ error: err.message });
        // Supprimer aussi les likes et commentaires liés
        db.run('DELETE FROM likes WHERE photo_id = ?', [id]);
        db.run('DELETE FROM comments WHERE photo_id = ?', [id]);
        res.json({ message: 'Photo supprimée' });
    });
});

// Nouvelle route : Gérer le J'aime (Toggle : ajoute ou retire)
app.post('/api/photos/:id/like', isAuthenticated, (req, res) => {
    const photoId = req.params.id;
    const userId = req.session.userId;
    
    db.get('SELECT * FROM likes WHERE user_id = ? AND photo_id = ?', [userId, photoId], (err, row) => {
        if (row) {
            db.run('DELETE FROM likes WHERE user_id = ? AND photo_id = ?', [userId, photoId], () => res.json({ liked: false }));
        } else {
            db.run('INSERT INTO likes (user_id, photo_id) VALUES (?, ?)', [userId, photoId], () => res.json({ liked: true }));
        }
    });
});

// Nouvelle route : Ajouter un commentaire
app.post('/api/photos/:id/comments', isAuthenticated, (req, res) => {
    const photoId = req.params.id;
    const { text } = req.body;
    if (!text || text.trim() === '') return res.status(400).json({ error: 'Texte vide' });
    
    db.get('SELECT full_name FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        const userName = user ? user.full_name : 'Anonyme';
        db.run('INSERT INTO comments (photo_id, user_id, user_name, text) VALUES (?, ?, ?, ?)',
            [photoId, req.session.userId, userName, text], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ success: true });
            });
    });
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`✅ Serveur démarré sur le port ${PORT}`));