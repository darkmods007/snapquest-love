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
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/audios', express.static(path.join(__dirname, 'audios')));

app.use(session({
    secret: 'snapquest_final_secret_2024',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: 'lax' }
}));

// ============ CRÉATION AUTOMATIQUE DES DOSSIERS uploads ET audios ============
const uploadsDir = path.join(__dirname, 'uploads');
const audiosDir = path.join(__dirname, 'audios');

if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log('📁 Dossier "uploads" créé automatiquement');
}

if (!fs.existsSync(audiosDir)) {
    fs.mkdirSync(audiosDir, { recursive: true });
    console.log('📁 Dossier "audios" créé automatiquement');
}

// ============ BASE DE DONNÉES ============
const db = new sqlite3.Database(path.join(__dirname, 'snapquest.db'));

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        full_name TEXT,
        profile_pic TEXT DEFAULT '',
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
    
    db.run(`CREATE TABLE IF NOT EXISTS global_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        user_name TEXT,
        text TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS audios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_url TEXT,
        title TEXT,
        artist TEXT,
        user_id INTEGER,
        user_name TEXT,
        created_date DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    console.log('✅ Base de données prête');
});

// Configuration multer
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (file.fieldname === 'audio') {
            cb(null, audiosDir);
        } else {
            cb(null, uploadsDir);
        }
    },
    filename: (req, file, cb) => {
        const unique = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, unique);
    }
});

const upload = multer({ storage });

// Middleware d'authentification
const isAuthenticated = (req, res, next) => {
    if (req.session.userId) return next();
    res.status(401).json({ error: "Non authentifie" });
};

// ============ ROUTES AUTH & PROFIL ============

app.post('/api/auth/register', (req, res) => {
    const { username, password, full_name } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: "Champs requis" });
    }
    
    const hash = bcrypt.hashSync(password, 10);
    db.run('INSERT INTO users (username, password, full_name) VALUES (?, ?, ?)', 
        [username, hash, full_name || username], 
        function(err) {
            if (err) {
                return res.status(400).json({ error: "Nom d'utilisateur deja pris" });
            }
            req.session.userId = this.lastID;
            res.json({ 
                user: { 
                    id: this.lastID, 
                    username, 
                    full_name: full_name || username, 
                    profile_pic: '' 
                } 
            });
        });
});

app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: "Identifiants invalides" });
        }
        
        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: "Identifiants invalides" });
        }
        
        req.session.userId = user.id;
        res.json({ 
            user: { 
                id: user.id, 
                username: user.username, 
                full_name: user.full_name, 
                profile_pic: user.profile_pic 
            } 
        });
    });
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/me', (req, res) => {
    if (!req.session.userId) return res.json(null);
    db.get('SELECT id, username, full_name, profile_pic FROM users WHERE id = ?', 
        [req.session.userId], 
        (err, user) => {
            if (err || !user) return res.json(null);
            res.json(user);
        });
});

app.post('/api/me/update', isAuthenticated, upload.single('file'), (req, res) => {
    const { username, full_name } = req.body;
    let query = 'UPDATE users SET username = ?, full_name = ?';
    let params = [username, full_name];
    
    if (req.file) {
        query += ', profile_pic = ?';
        params.push(`/uploads/${req.file.filename}`);
    }
    query += ' WHERE id = ?';
    params.push(req.session.userId);

    db.run(query, params, function(err) {
        if (err) {
            return res.status(400).json({ error: "Ce nom d'utilisateur est deja pris" });
        }
        db.get('SELECT id, username, full_name, profile_pic FROM users WHERE id = ?', 
            [req.session.userId], 
            (err, user) => {
                res.json({ user });
            });
    });
});

// ============ ROUTES PHOTOS ============

app.get('/api/photos', isAuthenticated, (req, res) => {
    const currentUserId = req.session.userId;
    
    const queryPhotos = `
        SELECT p.*, u.profile_pic as user_avatar, u.username as current_username, u.full_name as current_fullname
        FROM photos p 
        LEFT JOIN users u ON p.user_id = u.id 
        ORDER BY p.created_date DESC
    `;
    
    db.all(queryPhotos, [], (err, photos) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!photos || photos.length === 0) {
            return res.json([]);
        }
        
        db.all('SELECT * FROM likes', [], (err, allLikes) => {
            const queryComments = `
                SELECT c.*, u.profile_pic as user_avatar, u.username as current_username, u.full_name as current_fullname
                FROM comments c 
                LEFT JOIN users u ON c.user_id = u.id 
                ORDER BY c.created_at ASC
            `;
            db.all(queryComments, [], (err, allComments) => {
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
    if (!req.file) {
        return res.status(400).json({ error: "Image requise" });
    }
    
    const image_url = `/uploads/${req.file.filename}`;
    db.get('SELECT full_name FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        const userName = user ? user.full_name : 'Anonyme';
        db.run(
            'INSERT INTO photos (image_url, caption, user_id, user_name) VALUES (?, ?, ?, ?)',
            [image_url, req.body.caption || '', req.session.userId, userName],
            function(err) {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                res.json({ 
                    id: this.lastID, 
                    image_url, 
                    caption: req.body.caption, 
                    user_name: userName 
                });
            });
    });
});

app.delete('/api/photos/:id', isAuthenticated, (req, res) => {
    const { id } = req.params;
    db.run('DELETE FROM photos WHERE id = ? AND user_id = ?', [id, req.session.userId], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (this.changes === 0) {
            return res.status(403).json({ error: "Non autorise" });
        }
        
        db.run('DELETE FROM likes WHERE photo_id = ?', [id]);
        db.run('DELETE FROM comments WHERE photo_id = ?', [id]);
        res.json({ message: "Photo supprimee" });
    });
});

app.post('/api/photos/:id/like', isAuthenticated, (req, res) => {
    const photoId = req.params.id;
    const userId = req.session.userId;
    
    db.get('SELECT * FROM likes WHERE user_id = ? AND photo_id = ?', [userId, photoId], (err, row) => {
        if (row) {
            db.run('DELETE FROM likes WHERE user_id = ? AND photo_id = ?', [userId, photoId], () => {
                res.json({ liked: false });
            });
        } else {
            db.run('INSERT INTO likes (user_id, photo_id) VALUES (?, ?)', [userId, photoId], () => {
                res.json({ liked: true });
            });
        }
    });
});

app.post('/api/photos/:id/comments', isAuthenticated, (req, res) => {
    const photoId = req.params.id;
    const { text } = req.body;
    
    if (!text || text.trim() === '') {
        return res.status(400).json({ error: "Texte vide" });
    }
    
    db.get('SELECT full_name FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        db.run('INSERT INTO comments (photo_id, user_id, user_name, text) VALUES (?, ?, ?, ?)',
            [photoId, req.session.userId, user ? user.full_name : 'Anonyme', text], 
            function(err) {
                res.json({ success: true });
            });
    });
});

// ============ ROUTES MESSAGERIE ============

app.get('/api/messages', isAuthenticated, (req, res) => {
    const query = `
        SELECT m.*, u.profile_pic as user_avatar, u.username as current_username, u.full_name as current_fullname
        FROM (SELECT * FROM global_messages ORDER BY created_at DESC LIMIT 50) m
        LEFT JOIN users u ON m.user_id = u.id
        ORDER BY m.created_at ASC
    `;
    db.all(query, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows || []);
    });
});

app.post('/api/messages', isAuthenticated, (req, res) => {
    const { text } = req.body;
    
    if (!text || text.trim() === '') {
        return res.status(400).json({ error: "Texte vide" });
    }
    
    db.get('SELECT full_name FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        db.run('INSERT INTO global_messages (user_id, user_name, text) VALUES (?, ?, ?)',
            [req.session.userId, user ? user.full_name : 'Anonyme', text], 
            function(err) {
                res.json({ success: true });
            });
    });
});

// ============ ROUTES AUDIO ============

app.get('/api/audios', isAuthenticated, (req, res) => {
    const query = `
        SELECT a.*, u.profile_pic as user_avatar, u.username as current_username, u.full_name as current_fullname
        FROM audios a 
        LEFT JOIN users u ON a.user_id = u.id 
        ORDER BY a.created_date DESC
    `;
    db.all(query, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows || []);
    });
});

app.post('/api/audios', isAuthenticated, upload.single('audio'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: "Fichier audio requis" });
    }
    
    const file_url = `/audios/${req.file.filename}`;
    const { title, artist } = req.body;
    
    db.get('SELECT full_name FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        const userName = user ? user.full_name : 'Anonyme';
        db.run(
            'INSERT INTO audios (file_url, title, artist, user_id, user_name) VALUES (?, ?, ?, ?, ?)',
            [file_url, title || 'Sans titre', artist || 'Artiste inconnu', req.session.userId, userName],
            function(err) {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                res.json({ 
                    id: this.lastID, 
                    file_url, 
                    title: title || 'Sans titre', 
                    artist: artist || 'Artiste inconnu' 
                });
            });
    });
});

app.delete('/api/audios/:id', isAuthenticated, (req, res) => {
    const { id } = req.params;
    db.run('DELETE FROM audios WHERE id = ? AND user_id = ?', [id, req.session.userId], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: "Audio supprime" });
    });
});

// Route par défaut
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============ DÉMARRAGE ============
app.listen(PORT, () => {
    console.log(`✅ Serveur démarré sur le port ${PORT}`);
    console.log(`📁 Dossier uploads : ${uploadsDir}`);
    console.log(`🎵 Dossier audios : ${audiosDir}`);
});