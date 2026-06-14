<?php
// ─── Credentials ────────────────────────────────────────────────────────────
define('DB_HOST', '127.0.0.1');
define('DB_PORT', 3306);
define('DB_NAME', 'test');
define('DB_USER', 'meinsql');
define('DB_PASS', 'meinsql123');

define('ADMIN_USER', 'meinsql');
define('ADMIN_PASS', 'meinsql123');

define('ALLOW_DROP_TABLE', true);   // set to false to disable DROP TABLE
// ────────────────────────────────────────────────────────────────────────────

session_start();

// ─── Security helpers ────────────────────────────────────────────────────────
function csrfToken(): string {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}
function csrfCheck(): void {
    if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['_csrf'] ?? ''))
        die('Invalid CSRF token.');
}

function loginRateLimit(string $ip): bool {
    $key = 'login_fails_' . md5($ip);
    $data = $_SESSION[$key] ?? ['count' => 0, 'since' => time()];
    if (time() - $data['since'] > 600) $data = ['count' => 0, 'since' => time()];
    if ($data['count'] >= 5) return false;
    return true;
}
function loginRecordFail(string $ip): void {
    $key = 'login_fails_' . md5($ip);
    $data = $_SESSION[$key] ?? ['count' => 0, 'since' => time()];
    if (time() - $data['since'] > 600) $data = ['count' => 0, 'since' => time()];
    $data['count']++;
    $_SESSION[$key] = $data;
}
function loginClearFails(string $ip): void {
    unset($_SESSION['login_fails_' . md5($ip)]);
}

function deleteRateCheck(): bool {
    $data = $_SESSION['del_rate'] ?? ['count' => 0, 'since' => time()];
    if (time() - $data['since'] > 3600) $data = ['count' => 0, 'since' => time()];
    if ($data['count'] >= 50) return false;
    $data['count']++;
    $_SESSION['del_rate'] = $data;
    return true;
}
// ─────────────────────────────────────────────────────────────────────────────

// ─── Export SQL dump (GET, authenticated) ────────────────────────────────────
if (isset($_GET['action']) && $_GET['action'] === 'export_sql' && !empty($_SESSION['auth'])) {
    $onlyTable = $_GET['table'] ?? '';
    $tables    = ($onlyTable && validTable($onlyTable)) ? [$onlyTable] : getTables();
    $filename  = $onlyTable ? $onlyTable . '.sql' : DB_NAME . '_dump.sql';
    header('Content-Type: text/plain; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . preg_replace('/[^a-zA-Z0-9_.-]/', '_', $filename) . '"');
    echo "-- meinSQL dump\n-- Database: " . DB_NAME . "\n-- Date: " . date('Y-m-d H:i:s') . "\n\nSET FOREIGN_KEY_CHECKS=0;\n\n";
    foreach ($tables as $t) {
        echo "-- --------------------------------------------------------\n-- Table: `$t`\n\n";
        echo "DROP TABLE IF EXISTS " . quoteId($t) . ";\n";
        $create = db()->query('SHOW CREATE TABLE ' . quoteId($t))->fetch();
        echo $create['Create Table'] . ";\n\n";
        $rows = db()->query('SELECT * FROM ' . quoteId($t))->fetchAll();
        if ($rows) {
            $colList = implode(', ', array_map('quoteId', array_keys($rows[0])));
            foreach ($rows as $row) {
                $vals = array_map(function($v) {
                    if ($v === null) return 'NULL';
                    return "'" . str_replace(['\\', "'", "\n", "\r", "\x1a"], ['\\\\', "\\'", '\\n', '\\r', '\\Z'], $v) . "'";
                }, array_values($row));
                echo "INSERT INTO " . quoteId($t) . " ($colList) VALUES (" . implode(', ', $vals) . ");\n";
            }
            echo "\n";
        }
    }
    echo "SET FOREIGN_KEY_CHECKS=1;\n";
    exit;
}
// ─────────────────────────────────────────────────────────────────────────────

// ─── Export CSV (GET, authenticated) ─────────────────────────────────────────
if (isset($_GET['action']) && $_GET['action'] === 'export_csv' && !empty($_SESSION['auth'])) {
    $table = $_GET['table'] ?? '';
    if ($table && validTable($table)) {
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . preg_replace('/[^a-zA-Z0-9_-]/', '_', $table) . '.csv"');
        $out = fopen('php://output', 'w');
        $cols = getColumns($table);
        fputcsv($out, array_column($cols, 'Field'));
        $stmt = db()->query('SELECT * FROM ' . quoteId($table));
        while ($row = $stmt->fetch()) fputcsv($out, $row);
        fclose($out);
    }
    exit;
}
// ─────────────────────────────────────────────────────────────────────────────

// ─── Actions ────────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if ($_POST['action'] === 'login') {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        if (!loginRateLimit($ip)) {
            $loginError = 'Demasiadas tentativas. Aguarda 10 minutos.';
        } elseif ($_POST['username'] === ADMIN_USER && $_POST['password'] === ADMIN_PASS) {
            loginClearFails($ip);
            $_SESSION['auth'] = true;
            $_SESSION['user'] = ADMIN_USER;
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
        } else {
            loginRecordFail($ip);
            $loginError = 'Credenciais inválidas.';
        }
    }
    if ($_POST['action'] === 'logout') {
        if (!empty($_SESSION['auth'])) csrfCheck();
        session_destroy();
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }

    if (!empty($_SESSION['auth'])) {
      csrfCheck();
      try {
        if ($_POST['action'] === 'import_sql') {
            $file = $_FILES['sqlfile'] ?? null;
            if ($file && $file['error'] === UPLOAD_ERR_OK) {
                $sql   = file_get_contents($file['tmp_name']);
                $stmts = splitSql($sql);
                $ok = 0; $skipped = 0; $errs = [];
                foreach ($stmts as $s) {
                    if (!ALLOW_DROP_TABLE && preg_match('/^\s*DROP\s+TABLE\s/i', $s)) {
                        $skipped++; continue;
                    }
                    try { db()->exec($s); $ok++; }
                    catch (Exception $e) { $errs[] = $e->getMessage(); }
                }
                $_SESSION['flash_import'] = ['ok' => $ok, 'skipped' => $skipped, 'errors' => array_slice($errs, 0, 5)];
            } else {
                $_SESSION['flash_error'] = 'Ficheiro inválido ou erro no upload.';
            }
            $back = $_POST['table'] ?? '';
            header('Location: ' . $_SERVER['PHP_SELF'] . ($back ? '?table=' . urlencode($back) : ''));
            exit;
        }

        if ($_POST['action'] === 'run_query') {
            $sql = trim($_POST['sql'] ?? '');
            if ($sql) {
                $isSelect = preg_match('/^\s*(SELECT|SHOW|DESCRIBE|EXPLAIN)\s/i', $sql);
                if ($isSelect) {
                    $stmt = db()->query($sql);
                    $rows = $stmt->fetchAll();
                    $qCols = $rows ? array_keys($rows[0]) : ($stmt->getColumnMeta ? [] : []);
                    if (empty($qCols) && $rows) $qCols = array_keys($rows[0]);
                    $_SESSION['query_result'] = ['type' => 'select', 'sql' => $sql, 'rows' => array_slice($rows, 0, 500), 'cols' => $qCols, 'total' => count($rows)];
                } else {
                    $affected = db()->exec($sql);
                    $_SESSION['query_result'] = ['type' => 'exec', 'sql' => $sql, 'affected' => $affected];
                }
            }
            $back = $_POST['table'] ?? '';
            header('Location: ' . $_SERVER['PHP_SELF'] . ($back ? '?table=' . urlencode($back) : '') . '&qr=1');
            exit;
        }

        if ($_POST['action'] === 'drop_table') {
            $table   = $_POST['table']   ?? '';
            $confirm = $_POST['confirm'] ?? '';
            if (!ALLOW_DROP_TABLE) {
                $_SESSION['flash_error'] = 'DROP TABLE está desactivado nas configurações.';
            } elseif ($table && $confirm === $table && validTable($table)) {
                db()->exec('DROP TABLE ' . quoteId($table));
            }
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
        }

        if ($_POST['action'] === 'create_table') {
            $tbl  = preg_replace('/[^a-zA-Z0-9_]/', '', trim($_POST['tbl_name'] ?? ''));
            $names    = $_POST['col_names']    ?? [];
            $types    = $_POST['col_types']    ?? [];
            $customs  = $_POST['col_customs']  ?? [];
            $notnulls = $_POST['col_notnull']  ?? [];
            $uniques  = $_POST['col_unique']   ?? [];
            $defaults = $_POST['col_defaults'] ?? [];
            if ($tbl && $names) {
                $defs = ['`id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY'];
                foreach ($names as $i => $n) {
                    $n = preg_replace('/[^a-zA-Z0-9_]/', '', trim($n));
                    if (!$n) continue;
                    $t = $types[$i] ?? 'VARCHAR(255)';
                    if ($t === '__varchar_custom') {
                        $t = 'VARCHAR(' . (int)($customs[$i] ?? 255) . ')';
                    } elseif ($t === '__enum') {
                        $ev = array_map(fn($v) => "'" . str_replace("'","''",$v) . "'", explode(',', $customs[$i] ?? 'a'));
                        $t = 'ENUM(' . implode(',', $ev) . ')';
                    }
                    $allowed = ['INT','DOUBLE','TEXT','DATE','DATETIME'];
                    if (!in_array($t, $allowed) && !preg_match('/^(VARCHAR|ENUM)\(/i', $t)) continue;
                    $colDef  = '`' . $n . '` ' . strtoupper($t);
                    $colDef .= (($notnulls[$i] ?? '0') === '1') ? ' NOT NULL' : ' NULL';
                    if (!empty($defaults[$i])) {
                        $colDef .= ' DEFAULT ' . (is_numeric($defaults[$i]) ? $defaults[$i] : "'" . str_replace("'","''",$defaults[$i]) . "'");
                    }
                    if (($uniques[$i] ?? '0') === '1') $colDef .= ' UNIQUE';
                    $defs[] = $colDef;
                }
                db()->exec('CREATE TABLE IF NOT EXISTS `' . $tbl . '` (' . implode(', ', $defs) . ')');
            }
            header('Location: ' . $_SERVER['PHP_SELF'] . ($tbl ? '?table=' . urlencode($tbl) : ''));
            exit;
        }

        if ($_POST['action'] === 'add_column') {
            $table   = $_POST['table']   ?? '';
            $colName = trim($_POST['col_name'] ?? '');
            $colType = $_POST['col_type'] ?? '';
            if ($table && $colName && $colType && validTable($table)) {
                if ($colType === '__varchar_custom') $colType = 'VARCHAR(' . (int)($_POST['col_type_custom'] ?? 255) . ')';
                elseif ($colType === '__enum') {
                    $ev = array_map(fn($v) => "'" . str_replace("'", "''", trim($v)) . "'",
                                    explode(',', $_POST['col_type_custom'] ?? 'a'));
                    $colType = 'ENUM(' . implode(',', $ev) . ')';
                }
                $allowed = ['INT','DOUBLE','TEXT','DATE','DATETIME'];
                $def = in_array($colType, $allowed) ? $colType
                     : (preg_match('/^(VARCHAR|ENUM)\(/i', $colType) ? strtoupper($colType) : null);
                if ($def) {
                    $colDef  = quoteId($colName) . ' ' . $def;
                    $colDef .= !empty($_POST['col_notnull']) ? ' NOT NULL' : ' NULL';
                    if (!empty($_POST['col_default'])) {
                        $d = $_POST['col_default'];
                        $colDef .= ' DEFAULT ' . (is_numeric($d) ? $d : "'" . str_replace("'","''",$d) . "'");
                    }
                    if (!empty($_POST['col_unique'])) $colDef .= ' UNIQUE';
                    db()->exec('ALTER TABLE ' . quoteId($table) . ' ADD COLUMN ' . $colDef);
                }
            }
            header('Location: ' . $_SERVER['PHP_SELF'] . '?table=' . urlencode($table));
            exit;
        }

        if ($_POST['action'] === 'delete') {
            $table = $_POST['table'] ?? '';
            $pk    = $_POST['pk']    ?? '';
            $id    = $_POST['id']    ?? '';
            if ($table && $pk && $id !== '' && validTable($table)) {
                if (!deleteRateCheck()) {
                    $_SESSION['flash_error'] = 'Limite de 50 eliminações por hora atingido.';
                    header('Location: ' . $_SERVER['PHP_SELF'] . '?table=' . urlencode($table));
                    exit;
                }
                $stmt = db()->prepare('DELETE FROM ' . quoteId($table) . ' WHERE ' . quoteId($pk) . ' = ? LIMIT 1');
                $stmt->execute([$id]);
            }
            header('Location: ' . $_SERVER['PHP_SELF'] . '?table=' . urlencode($table));
            exit;
        }

        if ($_POST['action'] === 'insert') {
            $table = $_POST['table'] ?? '';
            $pk    = $_POST['pk']    ?? '';
            if ($table && validTable($table)) {
                $cols = getColumns($table);
                $fields = $vals = [];
                foreach ($cols as $col) {
                    $field = $col['Field'];
                    if (str_contains($col['Extra'] ?? '', 'auto_increment')) continue;
                    if (!array_key_exists($field, $_POST)) continue;
                    $posted = $_POST[$field];
                    $type   = strtolower($col['Type']);
                    if ($field === 'password' && $posted !== '') $posted = md5($posted);
                    if ($posted === '' && preg_match('/^(datetime|timestamp|date|time)/', $type)) {
                        $posted = date('Y-m-d H:i:s');
                    }
                    // skip empty fields that have a DB default (let DB fill them)
                    if ($posted === '' && $col['Default'] !== null) continue;
                    $fields[] = quoteId($field);
                    // NOT NULL + no default + empty → pass '' to avoid null constraint violation
                    $vals[]   = ($posted === '' && $col['Null'] === 'NO') ? '' : ($posted === '' ? null : $posted);
                }
                if ($fields) {
                    $placeholders = implode(', ', array_fill(0, count($vals), '?'));
                    $stmt = db()->prepare('INSERT INTO ' . quoteId($table) . ' (' . implode(', ', $fields) . ') VALUES (' . $placeholders . ')');
                    $stmt->execute($vals);
                }
            }
            header('Location: ' . $_SERVER['PHP_SELF'] . '?table=' . urlencode($table));
            exit;
        }

        if ($_POST['action'] === 'edit_save') {
            $table = $_POST['table'] ?? '';
            $pk    = $_POST['pk']    ?? '';
            $id    = $_POST['id']    ?? '';
            if ($table && $pk && $id !== '' && validTable($table)) {
                $cols = getColumns($table);
                $sets = [];
                $vals = [];
                foreach ($cols as $col) {
                    $field = $col['Field'];
                    if ($field === $pk) continue;
                    if (!array_key_exists($field, $_POST)) continue;
                    $posted = $_POST[$field];
                    $type   = strtolower($col['Type']);
                    if ($field === 'password') {
                        if ($posted === '') continue; // keep existing hash
                        $posted = md5($posted);
                    }
                    if ($posted === '' && preg_match('/^(datetime|timestamp|date|time)/', $type)) {
                        $posted = date('Y-m-d H:i:s');
                    }
                    $sets[] = quoteId($field) . ' = ?';
                    $vals[] = $posted === '' ? null : $posted;
                }
                if ($sets) {
                    $vals[] = $id;
                    $stmt = db()->prepare('UPDATE ' . quoteId($table) . ' SET ' . implode(', ', $sets) . ' WHERE ' . quoteId($pk) . ' = ?');
                    $stmt->execute($vals);
                }
            }
            header('Location: ' . $_SERVER['PHP_SELF'] . '?table=' . urlencode($table));
            exit;
        }
      } catch (Exception $e) {
          $_SESSION['flash_error'] = $e->getMessage();
          $back = $_POST['table'] ?? '';
          header('Location: ' . $_SERVER['PHP_SELF'] . ($back ? '?table=' . urlencode($back) : ''));
          exit;
      }
    }
}

$isAuth = !empty($_SESSION['auth']);

// ─── Helpers ─────────────────────────────────────────────────────────────────
function h(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
}

function db(): PDO {
    static $pdo;
    if (!$pdo) {
        $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', DB_HOST, DB_PORT, DB_NAME);
        $pdo = new PDO($dsn, DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    }
    return $pdo;
}

function splitSql(string $sql): array {
    $stmts = []; $cur = ''; $inStr = false; $strCh = '';
    for ($i = 0, $len = strlen($sql); $i < $len; $i++) {
        $c = $sql[$i];
        if (!$inStr && $c === '-' && ($sql[$i+1] ?? '') === '-') {
            $end = strpos($sql, "\n", $i); $i = $end === false ? $len : $end; continue;
        }
        if (!$inStr && $c === '/' && ($sql[$i+1] ?? '') === '*') {
            $end = strpos($sql, '*/', $i + 2); $i = $end === false ? $len : $end + 1; continue;
        }
        if ($inStr) {
            if ($c === '\\') { $cur .= $c . ($sql[++$i] ?? ''); }
            elseif ($c === $strCh) { $inStr = false; $cur .= $c; }
            else { $cur .= $c; }
        } else {
            if ($c === "'" || $c === '"') { $inStr = true; $strCh = $c; $cur .= $c; }
            elseif ($c === ';') { $s = trim($cur); if ($s !== '') $stmts[] = $s; $cur = ''; }
            else { $cur .= $c; }
        }
    }
    $s = trim($cur); if ($s !== '') $stmts[] = $s;
    return $stmts;
}

function validTable(string $table): bool {
    return in_array($table, getTables(), true);
}

function quoteId(string $name): string {
    return '`' . str_replace('`', '``', $name) . '`';
}

function getColumns(string $table): array {
    return db()->query('SHOW COLUMNS FROM ' . quoteId($table))->fetchAll();
}

function getPrimaryKey(string $table): ?string {
    foreach (getColumns($table) as $col) {
        if ($col['Key'] === 'PRI') return $col['Field'];
    }
    return null;
}

function searchWhere(string $table, string $search): array {
    if ($search === '') return ['', []];
    $parts = []; $params = [];
    foreach (getColumns($table) as $col) {
        if (preg_match('/^(varchar|char|text|tinytext|mediumtext|longtext|enum)/i', $col['Type'])) {
            $parts[] = quoteId($col['Field']) . ' LIKE ?';
            $params[] = '%' . $search . '%';
        }
    }
    return $parts ? ['WHERE (' . implode(' OR ', $parts) . ')', $params] : ['', []];
}

function countRows(string $table, string $search = ''): int {
    [$where, $params] = searchWhere($table, $search);
    if (!$where) return (int) db()->query('SELECT COUNT(*) FROM ' . quoteId($table))->fetchColumn();
    $stmt = db()->prepare('SELECT COUNT(*) FROM ' . quoteId($table) . " $where");
    $stmt->execute($params);
    return (int) $stmt->fetchColumn();
}

function getRows(string $table, int $page, int $perPage, ?string $sortCol, string $sortDir, string $search = ''): array {
    $offset  = ($page - 1) * $perPage;
    $orderBy = $sortCol ? ('ORDER BY ' . quoteId($sortCol) . ' ' . ($sortDir === 'desc' ? 'DESC' : 'ASC')) : '';
    [$where, $params] = searchWhere($table, $search);
    $params[] = $perPage;
    $params[] = $offset;
    $stmt = db()->prepare('SELECT * FROM ' . quoteId($table) . " $where $orderBy LIMIT ? OFFSET ?");
    foreach ($params as $i => $p)
        $stmt->bindValue($i + 1, $p, is_int($p) ? PDO::PARAM_INT : PDO::PARAM_STR);
    $stmt->execute();
    return $stmt->fetchAll();
}

function getTables(): array {
    $tables = db()->query('SHOW TABLES')->fetchAll(PDO::FETCH_COLUMN);
    if (empty($tables)) {
        $initFile = __DIR__ . '/init.sql';
        if (is_file($initFile)) {
            $sql = file_get_contents($initFile);
            foreach (array_filter(array_map('trim', explode(';', $sql))) as $stmt) {
                db()->exec($stmt);
            }
            $tables = db()->query('SHOW TABLES')->fetchAll(PDO::FETCH_COLUMN);
        }
    }
    return $tables;
}
// ─────────────────────────────────────────────────────────────────────────────
?>
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>meinSQL</title>
  <link href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.classless.min.css" rel="stylesheet">
  <style>
    /* ── Reset Pico body constraints ───────────────────────── */
    body { max-width:none; padding:0; margin:0; height:100vh; display:flex; flex-direction:column; overflow:hidden; }

    /* ── Top bar ───────────────────────────────────────────── */
    #topbar { display:flex; align-items:center; gap:.75rem; padding:.5rem 1rem;
              background:#1a1a2e; color:#fff; flex-shrink:0; }
    #topbar strong { margin-right:auto; font-size:1rem; color:#fff; }
    #topbar span   { font-size:.8rem; opacity:.6; color:#fff; }
    #topbar button, #topbar [role=button] { margin:0; padding:.25rem .65rem; font-size:.78rem; }
    #topbar form   { margin:0; }

    /* ── 3-pane layout ─────────────────────────────────────── */
    .layout { display:flex; flex:1; overflow:hidden; }
    .pane { display:flex; flex-direction:column; overflow:hidden; min-width:0; }
    .pane-inner { flex:1; overflow-y:auto; padding:.6rem; }
    .pane-header { display:flex; align-items:center; justify-content:space-between;
                   padding:.35rem .6rem; font-size:.68rem; font-weight:700;
                   text-transform:uppercase; letter-spacing:.06em; flex-shrink:0;
                   border-bottom:1px solid var(--pico-muted-border-color);
                   white-space:nowrap; overflow:hidden; color:var(--pico-muted-color); }
    .pane-title  { overflow:hidden; text-overflow:ellipsis; }
    .pane-divider { width:5px; cursor:col-resize; flex-shrink:0;
                    background:var(--pico-muted-border-color); transition:background .15s; }
    .pane-divider:hover, .pane-divider.dragging { background:var(--pico-primary); }
    .pane.collapsed { width:28px !important; }
    .pane.collapsed .pane-inner { display:none; }
    .pane.collapsed .pane-header { justify-content:center; padding:.35rem 0; }
    .pane.collapsed .pane-title  { display:none; }
    .collapse-btn { background:none; border:none; padding:0 0 0 .4rem; cursor:pointer;
                    color:var(--pico-muted-color); font-size:.75rem; flex-shrink:0; line-height:1; }
    .collapse-btn:hover { color:var(--pico-color); }
    .pane.collapsed .collapse-btn { padding:0; }

    /* ── Sidebar table links ───────────────────────────────── */
    .table-link { display:block; padding:.3rem .5rem; border-radius:var(--pico-border-radius);
                  text-decoration:none; color:var(--pico-color); font-size:.85rem; }
    .table-link:hover  { background:var(--pico-muted-background); }
    .table-link.active { background:var(--pico-primary); color:var(--pico-primary-inverse); }

    /* ── Schema table ──────────────────────────────────────── */
    .schema-table { font-size:.78rem; border-collapse:collapse; width:100%; }
    .schema-table th { color:var(--pico-muted-color); font-weight:500; padding:.2rem .4rem; border-bottom:1px solid var(--pico-muted-border-color); }
    .schema-table td { padding:.25rem .4rem; border-bottom:1px solid var(--pico-muted-border-color); vertical-align:middle; }
    .schema-table code { font-size:.72rem; }
    .badge { display:inline-block; font-size:.62rem; padding:.1rem .3rem;
             border-radius:.25rem; background:var(--pico-muted-background);
             color:var(--pico-muted-color); border:1px solid var(--pico-muted-border-color); }

    /* ── Records toolbar ───────────────────────────────────── */
    .toolbar { display:flex; align-items:center; gap:.5rem; flex-wrap:wrap; margin-bottom:.6rem; }
    .toolbar strong { margin-right:auto; }
    .toolbar button, .toolbar a[role=button] { margin:0; padding:.25rem .6rem; font-size:.78rem; }

    /* ── Col visibility dropdown ───────────────────────────── */
    details.col-picker { position:relative; }
    details.col-picker summary { padding:.25rem .6rem; font-size:.8rem; cursor:pointer;
                                  list-style:none; border:1px solid var(--pico-muted-border-color);
                                  border-radius:var(--pico-border-radius); }
    details.col-picker summary::after { content:' ▾'; }
    details.col-picker[open] summary::after { content:' ▴'; }
    .col-picker-menu { position:absolute; right:0; top:calc(100% + 4px); z-index:99;
                       background:var(--pico-background-color); border:1px solid var(--pico-muted-border-color);
                       border-radius:var(--pico-border-radius); padding:.4rem; min-width:150px;
                       box-shadow:0 4px 12px rgba(0,0,0,.15); }
    .col-picker-menu label { display:flex; align-items:center; gap:.4rem; padding:.2rem .3rem;
                              font-size:.82rem; cursor:pointer; white-space:nowrap; }
    .col-picker-menu label:hover { background:var(--pico-muted-background); border-radius:.25rem; }
    .col-picker-menu input { margin:0; width:auto; }

    /* ── Data table ────────────────────────────────────────── */
    #dataTable { font-size:.82rem; border-collapse:collapse; width:100%; }
    #dataTable th, #dataTable td { padding:.3rem .5rem; border:1px solid var(--pico-muted-border-color); }
    #dataTable thead { background:var(--pico-contrast-background); color:var(--pico-contrast-inverse-color); }
    #dataTable thead a { color:inherit; text-decoration:none; white-space:nowrap; }
    #dataTable thead a:hover { text-decoration:underline; }
    #dataTable tbody tr:hover { background:var(--pico-muted-background); }
    #dataTable td { max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    th.resizable { position:relative; overflow:hidden; min-width:60px; }
    th.resizable .col-resizer { position:absolute; right:0; top:0; bottom:0; width:5px;
                                cursor:col-resize; user-select:none; }
    th.resizable .col-resizer:hover { background:rgba(255,255,255,.3); }
    .action-cell { white-space:nowrap; }
    .action-cell a[role=button], .action-cell button {
      display:inline-flex; align-items:center; justify-content:center;
      margin:0 .1rem; padding:0; width:26px; height:26px;
      font-size:.95rem; line-height:1; border-radius:4px; }
    .action-cell form { display:inline; }

    /* ── Pagination ────────────────────────────────────────── */
    .pgbar { display:flex; align-items:center; gap:.4rem; flex-wrap:wrap; margin-top:.6rem; font-size:.82rem; }
    .pgbar a, .pgbar span { padding:.2rem .5rem; border:1px solid var(--pico-muted-border-color);
                            border-radius:var(--pico-border-radius); text-decoration:none;
                            color:var(--pico-color); }
    .pgbar a:hover  { background:var(--pico-muted-background); }
    .pgbar a.active { background:#1a1a2e; color:#fff; border-color:#1a1a2e; }
    .pgbar span     { color:var(--pico-muted-color); border-color:transparent; }
    .pgbar .pgsep   { border:none; color:var(--pico-muted-color); padding:.2rem 0; }
    .perpage { margin-left:auto; display:flex; align-items:center; gap:.3rem; }
    .perpage a, .perpage a.on { padding:.2rem .5rem; border:1px solid var(--pico-muted-border-color);
                                border-radius:var(--pico-border-radius); text-decoration:none; color:var(--pico-color); }
    .perpage a:hover { background:var(--pico-muted-background); }
    .perpage a.on   { background:#1a1a2e; color:#fff; border-color:#1a1a2e; }

    /* ── Dialog / modal ────────────────────────────────────── */
    dialog { max-width:480px; width:90%; padding:0; }
    dialog article { margin:0; }
    dialog header  { display:flex; align-items:center; justify-content:space-between; padding:.6rem 1rem;
                     border-bottom:1px solid var(--pico-muted-border-color); }
    dialog header h6 { margin:0; font-size:.9rem; }
    dialog .dialog-body { padding:.75rem 1rem; max-height:65vh; overflow-y:auto; }
    dialog footer  { display:flex; justify-content:flex-end; gap:.5rem; padding:.6rem 1rem;
                     border-top:1px solid var(--pico-muted-border-color); }
    dialog footer button, dialog footer a {
      display:inline-block; width:auto; margin:0; padding:.3rem .85rem;
      font-size:.82rem; border-radius:var(--pico-border-radius);
      cursor:pointer; text-decoration:none; line-height:1.5; }
    dialog footer .btn-cancel { background:#e0e0e0; color:#333; border:1px solid #ccc; }
    dialog footer .btn-cancel:hover { background:#d0d0d0; }
    dialog footer .btn-submit { background:#2e7d32; color:#fff; border:1px solid #2e7d32; }
    dialog footer .btn-submit:hover { background:#1b5e20; border-color:#1b5e20; }
    dialog label   { font-size:.82rem; font-weight:600; margin-bottom:.15rem; display:block; }
    dialog .hint   { font-size:.75rem; color:var(--pico-muted-color); margin-top:.2rem; }
    dialog input, dialog textarea, dialog select { margin-bottom:0; font-size:.83rem; padding:.35rem .5rem; }
    dialog .field  { margin-bottom:.65rem; }
    .col-flags { display:flex; gap:1rem; margin-top:.4rem; }
    .col-flags label { display:flex; align-items:center; gap:.3rem; font-size:.8rem; font-weight:400; cursor:pointer; }
    .col-flags input { width:auto; margin:0; }

    /* ── Login ─────────────────────────────────────────────── */
    #login-wrap { display:flex; align-items:center; justify-content:center; flex:1; }
    #login-wrap article { width:340px; }
    #login-wrap h4 { margin-bottom:.25rem; }
    #login-wrap p  { color:var(--pico-muted-color); margin-bottom:1.25rem; font-size:.85rem; }
    #login-wrap small.err { color:var(--pico-del-color); display:block; margin-bottom:.75rem; }
  </style>
</head>
<body>

<?php if (!$isAuth): ?>
<!-- ─── Login ──────────────────────────────────────────────────────────────── -->
<div id="login-wrap">
  <article>
    <h4>meinSQL</h4>
    <p>MySQL admin panel</p>
    <?php if (!empty($loginError)): ?>
      <small class="err"><?= h($loginError) ?></small>
    <?php endif ?>
    <form method="POST">
      <input type="hidden" name="action" value="login">
      <label>Username<input type="text" name="username" autofocus required></label>
      <label>Password<input type="password" name="password" required></label>
      <button type="submit">Login</button>
    </form>
  </article>
</div>

<?php else: ?>
<!-- ─── Dashboard ─────────────────────────────────────────────────────────── -->
<div id="topbar">
  <strong>meinSQL</strong>
  <span><?= h($_SESSION['user']) ?></span>
  <button id="themeToggle" title="Toggle theme">🌙</button>
  <a href="?action=export_sql" role="button" class="outline" title="Dump entire DB as SQL" style="font-size:.78rem;padding:.2rem .6rem">💾 Dump DB</a>
  <button type="button" class="outline" onclick="document.getElementById('importDialog').showModal()" style="font-size:.78rem;padding:.2rem .6rem;margin:0">📥 Import</button>
  <form method="POST">
    <input type="hidden" name="action" value="logout">
    <input type="hidden" name="_csrf" value="<?= h(csrfToken()) ?>">
    <button type="submit" class="secondary outline">Logout</button>
  </form>
</div>

<?php
$activeTable = isset($_GET['table']) && $_GET['table'] !== '' ? $_GET['table'] : null;
$cols = $pk = null;
if ($activeTable && validTable($activeTable)) {
    $cols = getColumns($activeTable);
    $pk   = getPrimaryKey($activeTable);
}
?>
<div class="layout">

  <!-- ── Pane 1: Tables ─────────────────────────────────────────────────── -->
  <div class="pane" id="paneLeft" style="width:180px;border-right:1px solid var(--pico-muted-border-color)">
    <div class="pane-header">
      <span class="pane-title">Tables</span>
      <div style="display:flex;gap:.3rem;align-items:center">
        <button class="collapse-btn" style="padding:0 .3rem;font-size:.7rem" onclick="document.getElementById('createTableDialog').showModal()">+</button>
        <button class="collapse-btn" data-pane="paneLeft">◀</button>
      </div>
    </div>
    <div class="pane-inner">
    <?php
    $dbError = null; $tables = [];
    try { $tables = getTables(); } catch (Exception $e) { $dbError = $e->getMessage(); }
    if ($dbError): ?>
      <small style="color:var(--pico-del-color)"><?= h($dbError) ?></small>
    <?php elseif (empty($tables)): ?>
      <small style="color:var(--pico-muted-color)">No tables.</small>
    <?php else: foreach ($tables as $t): ?>
      <a href="?table=<?= urlencode($t) ?>" class="table-link <?= $activeTable === $t ? 'active' : '' ?>">
        <?= h($t) ?>
      </a>
    <?php endforeach; endif ?>
    </div>
  </div>
  <div class="pane-divider" id="div1"></div>

  <!-- ── Pane 2: Schema ─────────────────────────────────────────────────── -->
  <div class="pane" id="paneMiddle" style="width:240px;border-right:1px solid var(--pico-muted-border-color)">
    <div class="pane-header">
      <span class="pane-title"><?= $activeTable ? h($activeTable) . ' — schema' : 'Schema' ?></span>
      <div style="display:flex;gap:.3rem;align-items:center">
        <?php if ($activeTable && $cols): ?>
          <button class="collapse-btn" style="padding:0 .3rem;font-size:.7rem" onclick="document.getElementById('addColDialog').showModal()" title="Add column">+</button>
          <?php if (ALLOW_DROP_TABLE): ?>
          <button class="collapse-btn" style="padding:0 .3rem;font-size:.7rem;color:#c62828" onclick="openDropTable('<?= h(addslashes($activeTable)) ?>')" title="Drop table">🗑</button>
          <?php endif ?>
        <?php endif ?>
        <button class="collapse-btn" data-pane="paneMiddle">◀</button>
      </div>
    </div>
    <div class="pane-inner">
    <?php if ($cols): ?>
      <table class="schema-table">
        <thead><tr><th>Column</th><th>Type</th><th>Key</th></tr></thead>
        <tbody>
        <?php foreach ($cols as $col): ?>
          <tr>
            <td><strong><?= h($col['Field']) ?></strong></td>
            <td><code><?= h($col['Type']) ?></code></td>
            <td><?= $col['Key'] ? '<span class="badge">' . h($col['Key']) . '</span>' : '' ?></td>
          </tr>
        <?php endforeach ?>
        </tbody>
      </table>
    <?php else: ?>
      <small style="color:var(--pico-muted-color)">Select a table.</small>
    <?php endif ?>
    </div>
  </div>
  <div class="pane-divider" id="div2"></div>

  <!-- ── Pane 3: Records ────────────────────────────────────────────────── -->
  <div class="pane" id="paneRight" style="flex:1">
    <div class="pane-header"><span class="pane-title">Records</span></div>
    <div class="pane-inner">
    <?php if (!empty($_SESSION['flash_error'])): ?>
      <div style="background:#ffebee;border:1px solid #ef9a9a;color:#b71c1c;padding:.5rem .75rem;border-radius:4px;font-size:.82rem;margin-bottom:.75rem">
        ⚠ <?= h($_SESSION['flash_error']) ?>
      </div>
      <?php unset($_SESSION['flash_error']); ?>
    <?php endif ?>
    <?php if (!empty($_SESSION['flash_import'])): $fi = $_SESSION['flash_import']; unset($_SESSION['flash_import']); ?>
      <div style="background:<?= empty($fi['errors']) ? '#e8f5e9' : '#fff8e1' ?>;border:1px solid <?= empty($fi['errors']) ? '#a5d6a7' : '#ffe082' ?>;color:<?= empty($fi['errors']) ? '#1b5e20' : '#e65100' ?>;padding:.5rem .75rem;border-radius:4px;font-size:.82rem;margin-bottom:.75rem">
        ✓ <?= $fi['ok'] ?> statement(s) executados com sucesso.<?= ($fi['skipped'] ?? 0) > 0 ? ' ' . $fi['skipped'] . ' DROP TABLE ignorado(s).' : '' ?>
        <?php foreach ($fi['errors'] as $err): ?><br><small>⚠ <?= h($err) ?></small><?php endforeach ?>
      </div>
    <?php endif ?>
  <?php if ($activeTable && $cols): ?>
    <?php
      $perPage  = in_array((int)($_GET['per'] ?? 0), [20,50,100]) ? (int)$_GET['per'] : 20;
      $page     = max(1, (int)($_GET['page'] ?? 1));
      $sortCol  = isset($_GET['sort']) && in_array($_GET['sort'], array_column($cols, 'Field'), true) ? $_GET['sort'] : null;
      $sortDir  = ($_GET['dir'] ?? 'asc') === 'desc' ? 'desc' : 'asc';
      $search   = trim($_GET['q'] ?? '');
      $total    = countRows($activeTable, $search);
      $pages    = max(1, (int)ceil($total / $perPage));
      $page     = min($page, $pages);
      $rows     = getRows($activeTable, $page, $perPage, $sortCol, $sortDir, $search);
      $editRow  = null; $isNewRow = false;
      if (isset($_GET['edit']) && $pk) {
          if ($_GET['edit'] === '__new__') {
              $isNewRow = true;
              $editRow  = array_fill_keys(array_column($cols, 'Field'), '');
          } else {
              $stmt = db()->prepare('SELECT * FROM ' . quoteId($activeTable) . ' WHERE ' . quoteId($pk) . ' = ? LIMIT 1');
              $stmt->execute([$_GET['edit']]);
              $editRow = $stmt->fetch() ?: null;
          }
      }
      $colFields = array_column($cols, 'Field');
      $pageBase  = '?table=' . urlencode($activeTable) . '&per=' . $perPage . ($sortCol ? '&sort=' . urlencode($sortCol) . '&dir=' . $sortDir : '') . ($search ? '&q=' . urlencode($search) : '');
    ?>

    <div class="toolbar">
      <strong><?= h($activeTable) ?> <small style="font-weight:400;color:var(--pico-muted-color)">(<?= $total ?>)</small></strong>
      <form method="GET" id="searchForm" style="display:flex;gap:.3rem;align-items:center;margin:0">
        <input type="hidden" name="table" value="<?= h($activeTable) ?>">
        <input type="hidden" name="per"   value="<?= $perPage ?>">
        <input type="text" name="q" id="searchInput" value="<?= h($search) ?>" placeholder="Search…" style="margin:0;padding:.2rem .5rem;font-size:.78rem;width:140px">
        <button type="submit" style="margin:0;padding:.2rem .5rem;font-size:.78rem">🔍</button>
        <?php if ($search): ?><a href="?table=<?= urlencode($activeTable) ?>" style="font-size:.78rem;padding:.2rem .4rem;border:1px solid var(--pico-muted-border-color);border-radius:4px;text-decoration:none;color:var(--pico-muted-color)" title="Clear">×</a><?php endif ?>
      </form>
      <?php if ($pk): ?>
        <a href="?table=<?= urlencode($activeTable) ?>&edit=__new__" role="button">+ Insert</a>
      <?php endif ?>
      <a href="?table=<?= urlencode($activeTable) ?>&action=export_csv" role="button" class="outline" title="Export CSV" style="font-size:.78rem;padding:.2rem .55rem">⬇ CSV</a>
      <a href="?table=<?= urlencode($activeTable) ?>&action=export_sql" role="button" class="outline" title="Export SQL dump" style="font-size:.78rem;padding:.2rem .55rem">⬇ SQL</a>
      <button type="button" class="outline" onclick="document.getElementById('sqlDialog').showModal()" style="font-size:.78rem;padding:.2rem .55rem;margin:0">⌨ SQL</button>
      <details class="col-picker">
        <summary>Columns</summary>
        <div class="col-picker-menu">
          <?php foreach ($colFields as $i => $f): ?>
            <label><input type="checkbox" class="col-toggle" data-col="<?= $i ?>" checked> <?= h($f) ?></label>
          <?php endforeach ?>
        </div>
      </details>
    </div>

    <?php if ($rows): ?>
    <div style="overflow-x:auto">
      <table id="dataTable">
        <thead><tr>
          <th style="width:80px">Actions</th>
          <?php foreach ($cols as $i => $col): $f = $col['Field'];
            $isSorted = $sortCol === $f;
            $nextDir  = ($isSorted && $sortDir === 'asc') ? 'desc' : 'asc';
            $arrow    = $isSorted ? ($sortDir === 'asc' ? ' ▲' : ' ▼') : '';
            $href     = '?table=' . urlencode($activeTable) . '&page=1&per=' . $perPage . '&sort=' . urlencode($f) . '&dir=' . $nextDir;
          ?>
            <th class="resizable" data-col="<?= $i ?>"><a href="<?= $href ?>"><?= h($f) . $arrow ?></a></th>
          <?php endforeach ?>
        </tr></thead>
        <tbody>
          <?php foreach ($rows as $row): ?>
          <tr>
            <td class="action-cell">
              <?php if ($pk): ?>
                <a href="?table=<?= urlencode($activeTable) ?>&page=<?= $page ?>&per=<?= $perPage ?>&edit=<?= urlencode($row[$pk]) ?>" role="button" class="outline" title="Edit">✏</a>
                <form method="POST" onsubmit="return confirm('Delete this row?')">
                  <input type="hidden" name="action" value="delete">
                  <input type="hidden" name="_csrf"  value="<?= h(csrfToken()) ?>">
                  <input type="hidden" name="table"  value="<?= h($activeTable) ?>">
                  <input type="hidden" name="pk"     value="<?= h($pk) ?>">
                  <input type="hidden" name="id"     value="<?= h($row[$pk]) ?>">
                  <button type="submit" title="Delete" style="background:#c62828;border-color:#c62828;color:#fff">🗑</button>
                </form>
              <?php endif ?>
            </td>
            <?php foreach ($cols as $i => $col): ?>
              <td data-col="<?= $i ?>"><?= h((string)($row[$col['Field']] ?? '')) ?></td>
            <?php endforeach ?>
          </tr>
          <?php endforeach ?>
        </tbody>
      </table>
    </div>

    <div class="pgbar">
      <?php if ($page > 1): ?><a href="<?= $pageBase ?>&page=<?= $page-1 ?>">‹</a><?php endif ?>
      <?php $range = range(max(1,$page-2), min($pages,$page+2));
            if (!in_array(1,$range)): ?><a href="<?= $pageBase ?>&page=1">1</a><?php if($range[0]>2): ?><span class="pgsep">…</span><?php endif; endif ?>
      <?php foreach ($range as $i): ?>
        <a href="<?= $pageBase ?>&page=<?= $i ?>" <?= $i===$page?'class="active"':'' ?>><?= $i ?></a>
      <?php endforeach ?>
      <?php if (!in_array($pages,$range)): ?><?php if(end($range)<$pages-1): ?><span class="pgsep">…</span><?php endif ?><a href="<?= $pageBase ?>&page=<?= $pages ?>"><?= $pages ?></a><?php endif ?>
      <?php if ($page < $pages): ?><a href="<?= $pageBase ?>&page=<?= $page+1 ?>">›</a><?php endif ?>
      <span><?= ($page-1)*$perPage+1 ?>–<?= min($page*$perPage,$total) ?> of <?= $total ?></span>
      <div class="perpage">
        Rows:
        <?php foreach ([20,50,100] as $opt): ?>
          <a href="?table=<?= urlencode($activeTable) ?>&page=1&per=<?= $opt ?><?= $sortCol?'&sort='.urlencode($sortCol).'&dir='.$sortDir:'' ?>" <?= $perPage===$opt?'class="on"':'' ?>><?= $opt ?></a>
        <?php endforeach ?>
      </div>
    </div>

    <?php else: ?>
      <p style="color:var(--pico-muted-color);font-size:.85rem">Table is empty.
        <?php if ($pk): ?><a href="?table=<?= urlencode($activeTable) ?>&edit=__new__" role="button" style="font-size:.8rem">+ Insert row</a><?php endif ?>
      </p>
    <?php endif ?>

  <?php else: ?>
    <p style="color:var(--pico-muted-color);font-size:.85rem">Select a table from the left.</p>
  <?php endif ?>
    </div>
  </div>

</div>

<!-- ─── Create Table dialog ───────────────────────────────────────────────── -->
<dialog id="createTableDialog">
  <article>
    <header>
      <h6>Create table</h6>
      <button type="button" class="btn-cancel" onclick="this.closest('dialog').close()" style="padding:.2rem .6rem;font-size:.85rem">×</button>
    </header>
    <form method="POST" id="createTableForm">
      <input type="hidden" name="action" value="create_table">
      <input type="hidden" name="_csrf"  value="<?= h(csrfToken()) ?>">
      <div class="dialog-body">
        <div class="field">
          <label>Table name</label>
          <input type="text" name="tbl_name" required placeholder="e.g. products" pattern="[a-zA-Z0-9_]+">
        </div>
        <div style="font-size:.78rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--pico-muted-color);margin-bottom:.4rem">
          Columns <small style="font-weight:400;text-transform:none">(id PK auto-added)</small>
        </div>
        <div id="ctCols">
          <div class="ct-row" style="margin-bottom:.6rem;padding:.4rem;border:1px solid var(--pico-muted-border-color);border-radius:4px">
            <div style="display:flex;gap:.4rem;align-items:center;margin-bottom:.3rem">
              <input type="text" name="col_names[]" placeholder="column name" style="flex:1;margin:0" pattern="[a-zA-Z0-9_]+">
              <select name="col_types[]" class="ct-type-sel" style="flex:1;margin:0">
                <option value="VARCHAR(255)" selected>VARCHAR(255)</option>
                <option value="INT">INT</option>
                <option value="DOUBLE">DOUBLE</option>
                <option value="TEXT">TEXT</option>
                <option value="DATE">DATE</option>
                <option value="DATETIME">DATETIME</option>
                <option value="__varchar_custom">VARCHAR(n)…</option>
                <option value="__enum">ENUM…</option>
              </select>
              <input type="text" name="col_customs[]" class="ct-custom" placeholder="" style="display:none;flex:1;margin:0">
              <button type="button" class="ct-remove" style="margin:0;padding:.2rem .5rem;background:#c62828;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.75rem">×</button>
            </div>
            <div style="display:flex;gap:.8rem;align-items:center;flex-wrap:wrap">
              <label style="display:flex;align-items:center;gap:.25rem;font-size:.78rem;font-weight:400;cursor:pointer;margin:0">
                <input type="checkbox" name="col_notnull[]" value="1" style="width:auto;margin:0"> NOT NULL</label>
              <label style="display:flex;align-items:center;gap:.25rem;font-size:.78rem;font-weight:400;cursor:pointer;margin:0">
                <input type="checkbox" name="col_unique[]" value="1" style="width:auto;margin:0"> UNIQUE</label>
              <input type="text" name="col_defaults[]" placeholder="DEFAULT" style="flex:1;margin:0;font-size:.78rem;padding:.2rem .4rem;min-width:80px">
            </div>
          </div>
        </div>
        <button type="button" id="ctAddCol" style="margin-top:.3rem;padding:.25rem .7rem;font-size:.78rem;background:#e8f5e9;color:#2e7d32;border:1px solid #a5d6a7;border-radius:var(--pico-border-radius);cursor:pointer">+ Add column</button>
      </div>
      <footer>
        <button type="button" class="btn-cancel" onclick="this.closest('dialog').close()">Cancel</button>
        <button type="submit" class="btn-submit">Create</button>
      </footer>
    </form>
  </article>
</dialog>

<?php if ($activeTable && $cols): ?>
<!-- ─── Add Column dialog ──────────────────────────────────────────────────── -->
<dialog id="addColDialog">
  <article>
    <header>
      <h6>Add column — <?= h($activeTable) ?></h6>
      <button type="button" class="btn-cancel" onclick="this.closest('dialog').close()" style="padding:.2rem .6rem;font-size:.85rem">×</button>
    </header>
    <form method="POST">
      <input type="hidden" name="action" value="add_column">
      <input type="hidden" name="_csrf"  value="<?= h(csrfToken()) ?>">
      <input type="hidden" name="table"  value="<?= h($activeTable) ?>">
      <div class="dialog-body">
        <div class="field">
          <label>Column name</label>
          <input type="text" name="col_name" required placeholder="e.g. status">
        </div>
        <div class="field">
          <label>Type</label>
          <select name="col_type" id="colTypeSelect">
            <option value="INT">INT</option>
            <option value="DOUBLE">DOUBLE</option>
            <option value="VARCHAR(255)" selected>VARCHAR(255)</option>
            <option value="TEXT">TEXT</option>
            <option value="DATE">DATE</option>
            <option value="__varchar_custom">VARCHAR(custom…)</option>
            <option value="__enum">ENUM(values…)</option>
          </select>
          <input type="text" id="colTypeCustom" name="col_type_custom" placeholder="e.g. 100 or 'a','b','c'" style="display:none;margin-top:.4rem">
        </div>
        <div class="field">
          <div class="col-flags">
            <label><input type="checkbox" name="col_notnull" value="1"> NOT NULL</label>
            <label><input type="checkbox" name="col_unique"  value="1"> UNIQUE</label>
          </div>
        </div>
        <div class="field">
          <label>Default <small style="font-weight:400;color:var(--pico-muted-color)">(optional)</small></label>
          <input type="text" name="col_default" placeholder="e.g. 0 or active">
        </div>
      </div>
      <footer>
        <button type="button" class="btn-cancel" onclick="this.closest('dialog').close()">Cancel</button>
        <button type="submit" class="btn-submit" id="addColSubmit">Add column</button>
      </footer>
    </form>
  </article>
</dialog>
<?php endif ?>

<?php
// Show query results if present
$queryResult = null;
if (isset($_GET['qr']) && !empty($_SESSION['query_result'])) {
    $queryResult = $_SESSION['query_result'];
    unset($_SESSION['query_result']);
}
?>
<?php if ($queryResult): ?>
<div id="queryResult" style="padding:.6rem;border-top:2px solid var(--pico-muted-border-color)">
  <div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.5rem">
    <strong style="font-size:.82rem">Query result</strong>
    <code style="font-size:.72rem;color:var(--pico-muted-color);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><?= h($queryResult['sql']) ?></code>
    <button type="button" onclick="this.closest('#queryResult').remove()" style="border:none;background:none;cursor:pointer;font-size:.85rem;color:var(--pico-muted-color)">×</button>
  </div>
  <?php if ($queryResult['type'] === 'exec'): ?>
    <p style="font-size:.82rem;color:#2e7d32">✓ <?= (int)$queryResult['affected'] ?> row(s) affected.</p>
  <?php else: ?>
    <?php if (empty($queryResult['rows'])): ?>
      <p style="font-size:.82rem;color:var(--pico-muted-color)">No rows returned.</p>
    <?php else: ?>
      <?php if ($queryResult['total'] > 500): ?><p style="font-size:.75rem;color:#e65100">Showing first 500 of <?= $queryResult['total'] ?> rows.</p><?php endif ?>
      <div style="overflow-x:auto">
        <table style="font-size:.78rem;border-collapse:collapse;width:100%">
          <thead><tr><?php foreach ($queryResult['cols'] as $c): ?><th style="padding:.25rem .4rem;border:1px solid var(--pico-muted-border-color);background:var(--pico-contrast-background);color:var(--pico-contrast-inverse-color)"><?= h($c) ?></th><?php endforeach ?></tr></thead>
          <tbody>
          <?php foreach ($queryResult['rows'] as $row): ?>
            <tr><?php foreach ($queryResult['cols'] as $c): ?><td style="padding:.2rem .4rem;border:1px solid var(--pico-muted-border-color);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><?= h((string)($row[$c] ?? '')) ?></td><?php endforeach ?></tr>
          <?php endforeach ?>
          </tbody>
        </table>
      </div>
    <?php endif ?>
  <?php endif ?>
</div>
<?php endif ?>

<?php if (!empty($editRow) && $pk): ?>
<!-- ─── Edit / Insert dialog ──────────────────────────────────────────────── -->
<dialog id="editDialog">
  <article>
    <header>
      <h6><?= $isNewRow ? 'Insert row' : 'Edit row' ?> — <?= h($activeTable) ?></h6>
      <a href="?table=<?= urlencode($activeTable) ?>&page=<?= $page ?? 1 ?>" style="text-decoration:none;font-size:1.2rem;line-height:1">×</a>
    </header>
    <form method="POST">
      <input type="hidden" name="action" value="<?= $isNewRow ? 'insert' : 'edit_save' ?>">
      <input type="hidden" name="_csrf"  value="<?= h(csrfToken()) ?>">
      <input type="hidden" name="table"  value="<?= h($activeTable) ?>">
      <input type="hidden" name="pk"     value="<?= h($pk) ?>">
      <?php if (!$isNewRow): ?>
        <input type="hidden" name="id" value="<?= h($editRow[$pk]) ?>">
      <?php endif ?>
      <div class="dialog-body">
        <?php foreach ($cols as $col):
          $field = $col['Field']; $val = (string)($editRow[$field] ?? '');
          $isPk  = $field === $pk; $isAutoInc = str_contains($col['Extra'] ?? '', 'auto_increment');
          $type  = strtolower($col['Type']);
        ?>
        <div class="field">
          <label><?= h($field) ?> <small style="font-weight:400;color:var(--pico-muted-color)">(<?= h($col['Type']) ?>)<?= $isPk?' PK':'' ?><?= $isAutoInc?' auto':'' ?></small></label>
          <?php if ($isPk && !$isNewRow): ?>
            <input type="text" value="<?= h($val) ?>" disabled>
          <?php elseif ($isPk && $isAutoInc): ?>
            <input type="text" value="auto" disabled>
          <?php elseif ($field === 'password'): ?>
            <input type="password" name="<?= h($field) ?>" placeholder="<?= $isNewRow ? 'Enter password' : 'Leave blank to keep current' ?>">
            <small class="hint">* Este campo será guardado encriptado</small>
          <?php elseif (str_starts_with($type, 'enum')): ?>
            <?php preg_match_all("/'([^']+)'/", $type, $m); ?>
            <select name="<?= h($field) ?>">
              <?php if ($col['Null'] === 'YES'): ?><option value="">— null —</option><?php endif ?>
              <?php foreach ($m[1] as $opt): ?>
                <option value="<?= h($opt) ?>" <?= $val === $opt ? 'selected' : '' ?>><?= h($opt) ?></option>
              <?php endforeach ?>
            </select>
          <?php elseif (str_contains($type, 'text')): ?>
            <textarea name="<?= h($field) ?>" rows="3"><?= h($val) ?></textarea>
          <?php elseif (str_starts_with($type, 'datetime') || str_starts_with($type, 'timestamp')): ?>
            <input type="datetime-local" name="<?= h($field) ?>" value="<?= h($val ? date('Y-m-d\TH:i', strtotime($val)) : date('Y-m-d\TH:i')) ?>">
          <?php elseif (str_starts_with($type, 'date')): ?>
            <input type="date" name="<?= h($field) ?>" value="<?= h($val ?: date('Y-m-d')) ?>">
          <?php elseif (str_starts_with($type, 'time')): ?>
            <input type="time" name="<?= h($field) ?>" value="<?= h($val) ?>">
          <?php elseif (str_starts_with($type, 'year')): ?>
            <input type="number" name="<?= h($field) ?>" min="1901" max="2155" value="<?= h($val) ?>">
          <?php elseif (preg_match('/^(tinyint|smallint|mediumint|int|bigint)/', $type)): ?>
            <input type="number" name="<?= h($field) ?>" value="<?= h($val) ?>">
          <?php elseif (preg_match('/^(float|double|decimal|numeric)/', $type)): ?>
            <input type="number" step="any" name="<?= h($field) ?>" value="<?= h($val) ?>">
          <?php else: ?>
            <input type="text" name="<?= h($field) ?>" value="<?= h($val) ?>">
          <?php endif ?>
        </div>
        <?php endforeach ?>
      </div>
      <footer>
        <a href="?table=<?= urlencode($activeTable) ?>&page=<?= $page ?? 1 ?>" role="button" class="btn-cancel">Cancel</a>
        <button type="submit" class="btn-submit"><?= $isNewRow ? 'Insert' : 'Save' ?></button>
      </footer>
    </form>
  </article>
</dialog>
<?php endif ?>

<!-- ─── Import SQL dialog ──────────────────────────────────────────────────── -->
<dialog id="importDialog">
  <article>
    <header>
      <h6>📥 Import SQL</h6>
      <button type="button" class="btn-cancel" onclick="this.closest('dialog').close()" style="padding:.2rem .6rem;font-size:.85rem">×</button>
    </header>
    <form method="POST" enctype="multipart/form-data">
      <input type="hidden" name="action" value="import_sql">
      <input type="hidden" name="_csrf"  value="<?= h(csrfToken()) ?>">
      <?php if ($activeTable ?? false): ?><input type="hidden" name="table" value="<?= h($activeTable) ?>"><?php endif ?>
      <div class="dialog-body">
        <div class="field">
          <label>Ficheiro .sql</label>
          <input type="file" name="sqlfile" accept=".sql,text/plain" required style="padding:.3rem 0">
        </div>
        <p style="font-size:.78rem;color:var(--pico-muted-color);margin:0">
          O ficheiro será executado statement a statement.<br>
          ⚠ Esta operação pode modificar ou destruir dados.
        </p>
      </div>
      <footer>
        <button type="button" class="btn-cancel" onclick="this.closest('dialog').close()">Cancel</button>
        <button type="submit" class="btn-submit" onclick="return confirm('Tens a certeza? Isto irá executar o SQL no ficheiro.')">Import</button>
      </footer>
    </form>
  </article>
</dialog>

<!-- ─── Drop Table dialog ───────────────────────────────────────────────────── -->
<dialog id="dropTableDialog">
  <article>
    <header>
      <h6 style="color:#c62828">⚠ Drop table</h6>
      <button type="button" class="btn-cancel" onclick="this.closest('dialog').close()" style="padding:.2rem .6rem;font-size:.85rem">×</button>
    </header>
    <form method="POST">
      <input type="hidden" name="action" value="drop_table">
      <input type="hidden" name="_csrf"  value="<?= h(csrfToken()) ?>">
      <input type="hidden" name="table"  id="dropTableName">
      <div class="dialog-body">
        <p style="font-size:.85rem;color:#c62828">This will permanently destroy the table and all its data. This action cannot be undone.</p>
        <div class="field">
          <label>Type <strong id="dropTableLabel" style="color:#c62828"></strong> to confirm</label>
          <input type="text" name="confirm" id="dropTableConfirm" autocomplete="off" placeholder="">
        </div>
      </div>
      <footer>
        <button type="button" class="btn-cancel" onclick="this.closest('dialog').close()">Cancel</button>
        <button type="submit" id="dropTableSubmit" class="btn-submit" style="background:#c62828;border-color:#c62828" disabled>Drop table</button>
      </footer>
    </form>
  </article>
</dialog>

<!-- ─── SQL Query dialog ────────────────────────────────────────────────────── -->
<dialog id="sqlDialog" style="max-width:640px">
  <article>
    <header>
      <h6>⌨ SQL Query</h6>
      <button type="button" class="btn-cancel" onclick="this.closest('dialog').close()" style="padding:.2rem .6rem;font-size:.85rem">×</button>
    </header>
    <form method="POST">
      <input type="hidden" name="action" value="run_query">
      <input type="hidden" name="_csrf"  value="<?= h(csrfToken()) ?>">
      <?php if ($activeTable): ?><input type="hidden" name="table" value="<?= h($activeTable) ?>"><?php endif ?>
      <div class="dialog-body">
        <div class="field">
          <label>SQL <small style="font-weight:400;color:var(--pico-muted-color)">SELECT returns up to 500 rows</small></label>
          <textarea name="sql" id="sqlInput" rows="5" placeholder="SELECT * FROM users LIMIT 10;" style="font-family:monospace;font-size:.82rem"></textarea>
        </div>
      </div>
      <footer>
        <button type="button" class="btn-cancel" onclick="this.closest('dialog').close()">Cancel</button>
        <button type="submit" class="btn-submit">Run</button>
      </footer>
    </form>
  </article>
</dialog>

<?php endif ?>

<script>
(function () {
  // ── Theme ───────────────────────────────────────────────────────────────
  const html = document.documentElement;
  const saved = localStorage.getItem('theme') || 'light';
  html.setAttribute('data-theme', saved);
  const themBtn = document.getElementById('themeToggle');
  if (themBtn) {
    themBtn.textContent = saved === 'dark' ? '☀' : '🌙';
    themBtn.onclick = () => {
      const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      html.setAttribute('data-theme', next);
      localStorage.setItem('theme', next);
      themBtn.textContent = next === 'dark' ? '☀' : '🌙';
    };
  }

  // ── Dialog auto-open ────────────────────────────────────────────────────
  const dlg = document.getElementById('editDialog');
  if (dlg) dlg.showModal();

  // ── Create Table — dynamic column rows ─────────────────────────────────
  function ctTypeToggle(sel) {
    const custom = sel.closest('.ct-row').querySelector('.ct-custom');
    if (sel.value === '__varchar_custom') {
      custom.style.display = ''; custom.type = 'number';
      custom.min = 1; custom.max = 65535; custom.placeholder = '256';
      if (!custom.value) custom.value = 256;
    } else if (sel.value === '__enum') {
      custom.style.display = ''; custom.type = 'text';
      custom.removeAttribute('min'); custom.removeAttribute('max');
      custom.placeholder = "e.g. active,inactive";
    } else {
      custom.style.display = 'none';
    }
  }
  function ctBindRow(row) {
    row.querySelector('.ct-type-sel').onchange = e => ctTypeToggle(e.target);
    row.querySelector('.ct-remove').onclick = () => {
      if (document.querySelectorAll('#ctCols .ct-row').length > 1) row.remove();
    };
  }
  document.querySelectorAll('#ctCols .ct-row').forEach(ctBindRow);
  document.getElementById('createTableForm')?.addEventListener('submit', () => {
    document.querySelectorAll('#ctCols .ct-row').forEach((row, i) => {
      const sel    = row.querySelector('select');
      const custom = row.querySelector('.ct-custom');
      if (sel.value === '__varchar_custom') sel.value = 'VARCHAR(' + (parseInt(custom.value) || 256) + ')';
      else if (sel.value === '__enum') sel.value = 'ENUM(' + custom.value.trim() + ')';
      // ensure unchecked checkboxes still submit an indexed value so PHP array indexes match
      ['col_notnull[]','col_unique[]'].forEach(n => {
        const cb = row.querySelector(`input[name="${n}"]`);
        if (cb && !cb.checked) {
          const h = document.createElement('input');
          h.type = 'hidden'; h.name = n; h.value = '0';
          row.appendChild(h);
          cb.disabled = true;
        }
      });
    });
  });
  document.getElementById('ctAddCol')?.addEventListener('click', () => {
    const tpl = document.querySelector('#ctCols .ct-row').cloneNode(true);
    tpl.querySelectorAll('input').forEach(i => { i.value = ''; i.style.display = i.classList.contains('ct-custom') ? 'none' : ''; });
    tpl.querySelector('select').value = 'VARCHAR(255)';
    document.getElementById('ctCols').appendChild(tpl);
    ctBindRow(tpl);
  });

  // ── Add Column — custom type toggle ─────────────────────────────────────
  function bindCustomType(sel, custom) {
    if (!sel || !custom) return;
    const update = () => {
      if (sel.value === '__varchar_custom') {
        custom.style.display = ''; custom.type = 'number';
        custom.min = 1; custom.max = 65535; custom.placeholder = '256';
        if (!custom.value) custom.value = 256;
      } else if (sel.value === '__enum') {
        custom.style.display = ''; custom.type = 'text';
        custom.removeAttribute('min'); custom.removeAttribute('max');
        custom.placeholder = "e.g. active,inactive";
      } else {
        custom.style.display = 'none';
      }
    };
    sel.onchange = update;
    sel.closest('form').addEventListener('submit', () => {
      if (sel.value === '__varchar_custom') sel.value = 'VARCHAR(' + (parseInt(custom.value) || 256) + ')';
      else if (sel.value === '__enum')      sel.value = 'ENUM(' + custom.value.trim() + ')';
    });
  }
  bindCustomType(document.getElementById('colTypeSelect'), document.getElementById('colTypeCustom'));

  // ── Drop table dialog ───────────────────────────────────────────────────
  window.openDropTable = function(name) {
    const dlg = document.getElementById('dropTableDialog');
    document.getElementById('dropTableName').value    = name;
    document.getElementById('dropTableLabel').textContent = name;
    document.getElementById('dropTableConfirm').value = '';
    document.getElementById('dropTableSubmit').disabled = true;
    dlg.showModal();
  };
  const dropConfirm = document.getElementById('dropTableConfirm');
  if (dropConfirm) {
    dropConfirm.oninput = function() {
      document.getElementById('dropTableSubmit').disabled =
        this.value !== document.getElementById('dropTableName').value;
    };
  }

  // ── SQL dialog — focus textarea on open ─────────────────────────────────
  const sqlDlg = document.getElementById('sqlDialog');
  if (sqlDlg) {
    sqlDlg.addEventListener('toggle', () => {
      if (sqlDlg.open) document.getElementById('sqlInput').focus();
    });
  }

  // ── Auto-scroll to query result if present ──────────────────────────────
  const qr = document.getElementById('queryResult');
  if (qr) qr.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  // ── Close col-picker when clicking outside ──────────────────────────────
  document.addEventListener('click', e => {
    document.querySelectorAll('details.col-picker[open]').forEach(d => {
      if (!d.contains(e.target)) d.removeAttribute('open');
    });
  });

  // ── Column visibility ───────────────────────────────────────────────────
  document.querySelectorAll('.col-toggle').forEach(cb => {
    cb.onchange = () => {
      document.querySelectorAll(`[data-col="${cb.dataset.col}"]`).forEach(el => {
        el.style.display = cb.checked ? '' : 'none';
      });
    };
  });

  // ── Table column resize ─────────────────────────────────────────────────
  document.querySelectorAll('th.resizable').forEach(th => {
    const r = document.createElement('div');
    r.className = 'col-resizer';
    th.appendChild(r);
    r.onmousedown = e => {
      const sx = e.pageX, sw = th.offsetWidth;
      const move = e2 => th.style.width = Math.max(60, sw + e2.pageX - sx) + 'px';
      document.addEventListener('mousemove', move);
      document.addEventListener('mouseup', () => document.removeEventListener('mousemove', move), {once:true});
      e.preventDefault();
    };
  });

  // ── Pane drag-resize ────────────────────────────────────────────────────
  ['div1:paneLeft', 'div2:paneMiddle'].forEach(pair => {
    const [divId, paneId] = pair.split(':');
    const div = document.getElementById(divId), pane = document.getElementById(paneId);
    if (!div || !pane) return;
    div.onmousedown = e => {
      div.classList.add('dragging');
      const sx = e.pageX, sw = pane.offsetWidth;
      const move = e2 => pane.style.width = Math.max(80, sw + e2.pageX - sx) + 'px';
      document.addEventListener('mousemove', move);
      document.addEventListener('mouseup', () => {
        div.classList.remove('dragging');
        document.removeEventListener('mousemove', move);
      }, {once:true});
      e.preventDefault();
    };
  });

  // ── Pane collapse ───────────────────────────────────────────────────────
  document.querySelectorAll('.collapse-btn').forEach(btn => {
    const pane = document.getElementById(btn.dataset.pane);
    if (!pane) return;
    btn.onclick = () => {
      const collapsed = pane.classList.toggle('collapsed');
      pane.style.width = collapsed ? '28px' : (pane.dataset.prevW || '200px');
      if (!collapsed) delete pane.dataset.prevW;
      else pane.dataset.prevW = pane.style.width;
      btn.textContent = collapsed ? '▶' : '◀';
    };
  });
})();
</script>
</body>
</html>
