CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    email      TEXT NOT NULL UNIQUE,
    password   TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin','user')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS visitors (
    id         INTEGER PRIMARY KEY,
    ip         TEXT NOT NULL,
    user_agent TEXT,
    url        TEXT,
    referer    TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS contacts (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    email      TEXT NOT NULL,
    subject    TEXT,
    message    TEXT NOT NULL,
    read_at    TEXT DEFAULT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO users (name, email, password, role) VALUES
    ('Alice Ferreira',  'alice@example.com',  '5ebe2294ecd0e0f08eab7690d2a6ee69', 'admin'),
    ('Bruno Costa',     'bruno@example.com',  '5ebe2294ecd0e0f08eab7690d2a6ee69', 'user'),
    ('Carla Mendes',    'carla@example.com',  '5ebe2294ecd0e0f08eab7690d2a6ee69', 'user'),
    ('David Santos',    'david@example.com',  '5ebe2294ecd0e0f08eab7690d2a6ee69', 'user'),
    ('Eva Rodrigues',   'eva@example.com',    '5ebe2294ecd0e0f08eab7690d2a6ee69', 'user');

INSERT OR IGNORE INTO visitors (ip, user_agent, url, referer) VALUES
    ('192.168.1.10', 'Mozilla/5.0 (Windows NT 10.0) Chrome/124.0', '/home',    'https://google.com'),
    ('192.168.1.11', 'Mozilla/5.0 (Macintosh) Safari/17.0',        '/about',   'https://twitter.com'),
    ('10.0.0.5',     'Mozilla/5.0 (Linux) Firefox/125.0',          '/contact', NULL),
    ('10.0.0.6',     'curl/8.1.0',                                  '/api',     NULL),
    ('192.168.1.12', 'Mozilla/5.0 (iPhone) Mobile Safari/604.1',   '/home',    'https://instagram.com');

INSERT OR IGNORE INTO contacts (name, email, subject, message) VALUES
    ('Ana Lima',       'ana@example.com',    'Orçamento',        'Bom dia, gostaria de saber o preço dos vossos serviços.'),
    ('Pedro Gomes',    'pedro@example.com',  'Parceria',         'Olá, tenho interesse em explorar uma possível parceria.'),
    ('Sofia Martins',  'sofia@example.com',  'Suporte técnico',  'O formulário de contacto do site não está a funcionar.'),
    ('Rui Andrade',    'rui@example.com',    NULL,               'Simplesmente adorei o vosso trabalho, parabéns!'),
    ('Lara Neves',     'lara@example.com',   'Demo',             'Podem agendar uma demonstração do produto?');
