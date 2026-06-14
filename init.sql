CREATE TABLE IF NOT EXISTS users (
    id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name       VARCHAR(100) NOT NULL,
    email      VARCHAR(150) NOT NULL UNIQUE,
    password   VARCHAR(255) NOT NULL,
    role       ENUM('admin','user') NOT NULL DEFAULT 'user',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS visitors (
    id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip         VARCHAR(45) NOT NULL,
    user_agent TEXT,
    url        VARCHAR(500),
    referer    VARCHAR(500),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS contacts (
    id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name       VARCHAR(100) NOT NULL,
    email      VARCHAR(150) NOT NULL,
    subject    VARCHAR(200),
    message    TEXT NOT NULL,
    read_at    DATETIME DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT IGNORE INTO users (name, email, password, role) VALUES
    ('Alice Ferreira',  'alice@example.com',  MD5('secret'),  'admin'),
    ('Bruno Costa',     'bruno@example.com',  MD5('secret'),  'user'),
    ('Carla Mendes',    'carla@example.com',  MD5('secret'),  'user'),
    ('David Santos',    'david@example.com',  MD5('secret'),  'user'),
    ('Eva Rodrigues',   'eva@example.com',    MD5('secret'),  'user');

INSERT IGNORE INTO visitors (ip, user_agent, url, referer) VALUES
    ('192.168.1.10', 'Mozilla/5.0 (Windows NT 10.0) Chrome/124.0', '/home',    'https://google.com'),
    ('192.168.1.11', 'Mozilla/5.0 (Macintosh) Safari/17.0',        '/about',   'https://twitter.com'),
    ('10.0.0.5',     'Mozilla/5.0 (Linux) Firefox/125.0',          '/contact', NULL),
    ('10.0.0.6',     'curl/8.1.0',                                  '/api',     NULL),
    ('192.168.1.12', 'Mozilla/5.0 (iPhone) Mobile Safari/604.1',   '/home',    'https://instagram.com');

INSERT IGNORE INTO contacts (name, email, subject, message) VALUES
    ('Ana Lima',       'ana@example.com',    'Orçamento',         'Bom dia, gostaria de saber o preço dos vossos serviços.'),
    ('Pedro Gomes',    'pedro@example.com',  'Parceria',          'Olá, tenho interesse em explorar uma possível parceria.'),
    ('Sofia Martins',  'sofia@example.com',  'Suporte técnico',   'O formulário de contacto do site não está a funcionar.'),
    ('Rui Andrade',    'rui@example.com',    NULL,                 'Simplesmente adorei o vosso trabalho, parabéns!'),
    ('Lara Neves',     'lara@example.com',   'Demo',              'Podem agendar uma demonstração do produto?');
