from flask import Flask, request, jsonify, session, render_template, send_from_directory
from flask_cors import CORS
import sqlite3
import os
from datetime import datetime, timedelta
import hashlib
import secrets

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app, supports_credentials=True)

# Secret key for session management
app.secret_key = secrets.token_hex(32)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

DB_PATH = "splitpay.db"

# ══════════════════════════════════════════
#  DATABASE SETUP
# ══════════════════════════════════════════

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Return rows as dicts
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    # Users table for authentication
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    NOT NULL UNIQUE,
            email       TEXT    NOT NULL UNIQUE,
            password    TEXT    NOT NULL,
            created_at  TEXT    DEFAULT (datetime('now')),
            last_login  TEXT    DEFAULT NULL
        )
    ''')

    # Groups table
    c.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            description TEXT    DEFAULT '',
            icon        TEXT    DEFAULT '🎉',
            created_by  INTEGER NOT NULL,
            created_at  TEXT    DEFAULT (datetime('now')),
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Group members - linking users to groups
    c.execute('''
        CREATE TABLE IF NOT EXISTS group_members (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id   INTEGER NOT NULL,
            user_id    INTEGER NOT NULL,
            joined_at  TEXT    DEFAULT (datetime('now')),
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(group_id, user_id)
        )
    ''')

    # Members table (kept for backward compatibility with existing code)
    c.execute('''
        CREATE TABLE IF NOT EXISTS members (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id   INTEGER NOT NULL,
            name       TEXT    NOT NULL,
            email      TEXT    DEFAULT '',
            joined_at  TEXT    DEFAULT (datetime('now')),
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
            UNIQUE(group_id, name)
        )
    ''')

    # Expenses table
    c.execute('''
        CREATE TABLE IF NOT EXISTS expenses (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id    INTEGER NOT NULL,
            description TEXT    NOT NULL,
            amount      REAL    NOT NULL,
            paid_by     TEXT    NOT NULL,
            category    TEXT    DEFAULT 'Other',
            created_at  TEXT    DEFAULT (datetime('now')),
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
        )
    ''')

    # Expense splits table (who owes what for each expense)
    c.execute('''
        CREATE TABLE IF NOT EXISTS expense_splits (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            expense_id  INTEGER NOT NULL,
            member_name TEXT    NOT NULL,
            share       REAL    NOT NULL,
            is_paid     INTEGER DEFAULT 0,
            FOREIGN KEY (expense_id) REFERENCES expenses(id) ON DELETE CASCADE
        )
    ''')

    conn.commit()
    conn.close()
    print("✅ Database initialized.")


# ══════════════════════════════════════════
#  AUTHENTICATION HELPER FUNCTIONS
# ══════════════════════════════════════════

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password, hashed):
    """Verify password against hash"""
    return hash_password(password) == hashed


def is_logged_in():
    """Check if user is logged in"""
    return 'user_id' in session


def get_current_user():
    """Get current logged in user info"""
    if not is_logged_in():
        return None
    
    conn = get_db()
    c = conn.cursor()
    user = c.execute(
        "SELECT id, username, email, created_at FROM users WHERE id = ?",
        (session['user_id'],)
    ).fetchone()
    conn.close()
    
    return dict(user) if user else None


def login_required(f):
    """Decorator to require login for routes"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


# ══════════════════════════════════════════
#  SERVE HTML FILES
# ══════════════════════════════════════════

@app.route('/')
def index():
    """Serve login page"""
    return send_from_directory('.', 'login.html')

@app.route('/login.html')
def login_page():
    """Serve login page"""
    return send_from_directory('.', 'login.html')

@app.route('/dashboard.html')
def dashboard_page():
    """Serve dashboard page"""
    return send_from_directory('.', 'dashboard.html')

@app.route('/groups.html')
def groups_page():
    """Serve groups page"""
    return send_from_directory('.', 'groups.html')

@app.route('/settings.html')
def settings_page():
    """Serve settings page"""
    return send_from_directory('.', 'settings.html')

@app.route('/index.html')
def index_page():
    """Serve index page"""
    return send_from_directory('.', 'index.html')

@app.route('/landing.html')
def landing_page():
    """Serve landing page"""
    return send_from_directory('.', 'landing.html')


# ══════════════════════════════════════════
#  AUTHENTICATION ROUTES
# ══════════════════════════════════════════

@app.route('/auth/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.json
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '').strip()
    
    # Validation
    if not username or len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    
    if not email or '@' not in email:
        return jsonify({'error': 'Valid email is required'}), 400
    
    if not password or len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    # Check if username exists
    existing_user = c.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()
    
    if existing_user:
        conn.close()
        return jsonify({'error': 'Username already exists'}), 409
    
    # Check if email exists
    existing_email = c.execute(
        "SELECT id FROM users WHERE email = ?", (email,)
    ).fetchone()
    
    if existing_email:
        conn.close()
        return jsonify({'error': 'Email already registered'}), 409
    
    # Hash password and create user
    hashed_password = hash_password(password)
    
    try:
        c.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, hashed_password)
        )
        user_id = c.lastrowid
        conn.commit()
        
        # Get the created user
        user = dict(c.execute(
            "SELECT id, username, email, created_at FROM users WHERE id = ?",
            (user_id,)
        ).fetchone())
        
        conn.close()
        
        # Log the user in automatically
        session.permanent = True
        session['user_id'] = user_id
        session['username'] = username
        
        return jsonify({
            'message': 'Registration successful',
            'user': user
        }), 201
        
    except Exception as e:
        conn.close()
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500


@app.route('/auth/login', methods=['POST'])
def login():
    """Login user"""
    data = request.json
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    # Find user
    user = c.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    
    if not user:
        conn.close()
        return jsonify({'error': 'Invalid username or password'}), 401
    
    user = dict(user)
    
    # Verify password
    if not verify_password(password, user['password']):
        conn.close()
        return jsonify({'error': 'Invalid username or password'}), 401
    
    # Update last login
    c.execute(
        "UPDATE users SET last_login = datetime('now') WHERE id = ?",
        (user['id'],)
    )
    conn.commit()
    conn.close()
    
    # Create session
    session.permanent = True
    session['user_id'] = user['id']
    session['username'] = user['username']
    
    return jsonify({
        'message': 'Login successful',
        'user': {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'created_at': user['created_at']
        }
    }), 200


@app.route('/auth/logout', methods=['POST'])
def logout():
    """Logout user"""
    session.clear()
    return jsonify({'message': 'Logout successful'}), 200


@app.route('/auth/me', methods=['GET'])
@login_required
def get_me():
    """Get current logged in user"""
    user = get_current_user()
    if user:
        return jsonify(user), 200
    return jsonify({'error': 'User not found'}), 404


@app.route('/auth/check', methods=['GET'])
def check_auth():
    """Check if user is authenticated"""
    if is_logged_in():
        user = get_current_user()
        return jsonify({
            'authenticated': True,
            'user': user
        }), 200
    return jsonify({'authenticated': False}), 200


# ══════════════════════════════════════════
#  HELPER FUNCTIONS
# ══════════════════════════════════════════

def row_to_dict(row):
    return dict(row) if row else None


def rows_to_list(rows):
    return [dict(r) for r in rows]


def compute_balances(group_id):
    """Compute net balance for each member in a group."""
    conn = get_db()
    c = conn.cursor()

    members = rows_to_list(c.execute(
        "SELECT name FROM members WHERE group_id = ?", (group_id,)
    ).fetchall())

    expenses = rows_to_list(c.execute(
        "SELECT * FROM expenses WHERE group_id = ?", (group_id,)
    ).fetchall())

    conn.close()

    if not members or not expenses:
        return {}

    balances = {m['name']: 0.0 for m in members}
    member_count = len(members)

    for exp in expenses:
        share = exp['amount'] / member_count
        # Payer gets credited full amount
        if exp['paid_by'] in balances:
            balances[exp['paid_by']] += exp['amount']
        # Everyone owes their share
        for m in members:
            balances[m['name']] -= share

    return {k: round(v, 2) for k, v in balances.items()}


def compute_settlements(group_id):
    """Compute minimum transactions to settle all debts."""
    balances = compute_balances(group_id)
    if not balances:
        return []

    debtors  = sorted([(n, -b) for n, b in balances.items() if b < -0.01], key=lambda x: -x[1])
    creditors = sorted([(n, b)  for n, b in balances.items() if b >  0.01], key=lambda x: -x[1])

    transactions = []
    i, j = 0, 0

    while i < len(debtors) and j < len(creditors):
        debtor_name,   debt   = debtors[i]
        creditor_name, credit = creditors[j]
        payment = round(min(debt, credit), 2)

        transactions.append({
            'from':   debtor_name,
            'to':     creditor_name,
            'amount': payment
        })

        debtors[i]   = (debtor_name,   round(debt   - payment, 2))
        creditors[j] = (creditor_name, round(credit - payment, 2))

        if debtors[i][1]   < 0.01: i += 1
        if creditors[j][1] < 0.01: j += 1

    return transactions


def get_group_summary(group_id):
    """Return full group data with stats."""
    conn = get_db()
    c = conn.cursor()

    group = row_to_dict(c.execute(
        "SELECT * FROM groups WHERE id = ?", (group_id,)
    ).fetchone())

    if not group:
        conn.close()
        return None

    members = rows_to_list(c.execute(
        "SELECT * FROM members WHERE group_id = ?", (group_id,)
    ).fetchall())

    expenses = rows_to_list(c.execute(
        "SELECT * FROM expenses WHERE group_id = ? ORDER BY created_at DESC",
        (group_id,)
    ).fetchall())

    conn.close()

    total_amount = sum(e['amount'] for e in expenses)

    group['members']      = members
    group['expenses']     = expenses
    group['member_count'] = len(members)
    group['expense_count']= len(expenses)
    group['total_amount'] = round(total_amount, 2)
    group['balances']     = compute_balances(group_id)
    group['settlements']  = compute_settlements(group_id)

    return group


# ══════════════════════════════════════════
#  ROUTES — GROUPS
# ══════════════════════════════════════════

@app.route('/groups', methods=['GET'])
@login_required
def get_groups():
    """Get all groups for current user."""
    user_id = session['user_id']
    
    conn = get_db()
    c = conn.cursor()
    
    # Get groups where user is a member or creator
    groups = rows_to_list(c.execute('''
        SELECT DISTINCT g.* FROM groups g
        LEFT JOIN group_members gm ON g.id = gm.group_id
        WHERE g.created_by = ? OR gm.user_id = ?
        ORDER BY g.created_at DESC
    ''', (user_id, user_id)).fetchall())
    
    conn.close()

    # Attach stats to each group
    result = []
    for g in groups:
        summary = get_group_summary(g['id'])
        if summary:
            result.append(summary)

    return jsonify(result), 200


@app.route('/groups', methods=['POST'])
@login_required
def create_group():
    """Create a new group."""
    data = request.json
    user_id = session['user_id']

    if not data or not data.get('name', '').strip():
        return jsonify({'error': 'Group name is required'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO groups (name, description, icon, created_by) VALUES (?, ?, ?, ?)",
        (
            data['name'].strip(),
            data.get('description', '').strip(),
            data.get('icon', '🎉'),
            user_id
        )
    )
    group_id = c.lastrowid
    
    # Add creator as a member
    c.execute(
        "INSERT INTO group_members (group_id, user_id) VALUES (?, ?)",
        (group_id, user_id)
    )
    
    conn.commit()
    conn.close()

    return jsonify(get_group_summary(group_id)), 201


@app.route('/groups/<int:group_id>', methods=['GET'])
@login_required
def get_group(group_id):
    """Get a single group with full details."""
    summary = get_group_summary(group_id)
    if not summary:
        return jsonify({'error': 'Group not found'}), 404
    return jsonify(summary), 200


@app.route('/groups/<int:group_id>', methods=['PUT'])
@login_required
def update_group(group_id):
    """Update group name/description/icon."""
    data = request.json
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    conn = get_db()
    c = conn.cursor()

    group = c.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
    if not group:
        conn.close()
        return jsonify({'error': 'Group not found'}), 404

    # Build update query dynamically
    updates = []
    values = []
    if 'name' in data and data['name'].strip():
        updates.append("name = ?")
        values.append(data['name'].strip())
    if 'description' in data:
        updates.append("description = ?")
        values.append(data['description'].strip())
    if 'icon' in data:
        updates.append("icon = ?")
        values.append(data['icon'].strip())

    if not updates:
        conn.close()
        return jsonify({'error': 'No valid fields to update'}), 400

    values.append(group_id)
    c.execute(f"UPDATE groups SET {', '.join(updates)} WHERE id = ?", values)
    conn.commit()
    conn.close()

    return jsonify(get_group_summary(group_id)), 200


@app.route('/groups/<int:group_id>', methods=['DELETE'])
@login_required
def delete_group(group_id):
    """Delete a group."""
    conn = get_db()
    c = conn.cursor()

    group = c.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
    if not group:
        conn.close()
        return jsonify({'error': 'Group not found'}), 404

    c.execute("DELETE FROM groups WHERE id = ?", (group_id,))
    conn.commit()
    conn.close()

    return jsonify({'message': f'Group "{group["name"]}" deleted'}), 200


# ══════════════════════════════════════════
#  ROUTES — MEMBERS
# ══════════════════════════════════════════

@app.route('/groups/<int:group_id>/members', methods=['GET'])
@login_required
def get_members(group_id):
    """Get all members of a group."""
    conn = get_db()
    c = conn.cursor()

    if not c.execute("SELECT id FROM groups WHERE id = ?", (group_id,)).fetchone():
        conn.close()
        return jsonify({'error': 'Group not found'}), 404

    members = rows_to_list(c.execute(
        "SELECT * FROM members WHERE group_id = ? ORDER BY joined_at",
        (group_id,)
    ).fetchall())
    conn.close()

    return jsonify(members), 200


@app.route('/groups/<int:group_id>/members', methods=['POST'])
@login_required
def add_member(group_id):
    """Add a member to a group."""
    data = request.json

    if not data or not data.get('name', '').strip():
        return jsonify({'error': 'Member name is required'}), 400

    conn = get_db()
    c = conn.cursor()

    if not c.execute("SELECT id FROM groups WHERE id = ?", (group_id,)).fetchone():
        conn.close()
        return jsonify({'error': 'Group not found'}), 404

    try:
        c.execute(
            "INSERT INTO members (group_id, name, email) VALUES (?, ?, ?)",
            (group_id, data['name'].strip(), data.get('email', '').strip())
        )
        member_id = c.lastrowid
        conn.commit()

        member = row_to_dict(c.execute(
            "SELECT * FROM members WHERE id = ?", (member_id,)
        ).fetchone())
        conn.close()

        return jsonify(member), 201

    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': f'Member "{data["name"]}" already exists in this group'}), 409


@app.route('/groups/<int:group_id>/members/<int:member_id>', methods=['DELETE'])
@login_required
def remove_member(group_id, member_id):
    """Remove a member from a group."""
    conn = get_db()
    c = conn.cursor()

    member = c.execute(
        "SELECT * FROM members WHERE id = ? AND group_id = ?",
        (member_id, group_id)
    ).fetchone()

    if not member:
        conn.close()
        return jsonify({'error': 'Member not found'}), 404

    member = dict(member)

    # Check if member has any expenses
    has_expenses = c.execute(
        "SELECT COUNT(*) FROM expenses WHERE group_id = ? AND paid_by = ?",
        (group_id, member['name'])
    ).fetchone()[0]

    if has_expenses > 0:
        conn.close()
        return jsonify({
            'error': f'Cannot remove "{member["name"]}" - they have expenses recorded'
        }), 400

    c.execute("DELETE FROM members WHERE id = ?", (member_id,))
    conn.commit()
    conn.close()

    return jsonify({'message': f'Member "{member["name"]}" removed'}), 200


# ══════════════════════════════════════════
#  ROUTES — EXPENSES
# ══════════════════════════════════════════

@app.route('/groups/<int:group_id>/expenses', methods=['GET'])
@login_required
def get_expenses(group_id):
    """Get all expenses for a group."""
    conn = get_db()
    c = conn.cursor()

    if not c.execute("SELECT id FROM groups WHERE id = ?", (group_id,)).fetchone():
        conn.close()
        return jsonify({'error': 'Group not found'}), 404

    expenses = rows_to_list(c.execute(
        "SELECT * FROM expenses WHERE group_id = ? ORDER BY created_at DESC",
        (group_id,)
    ).fetchall())
    conn.close()

    return jsonify(expenses), 200


@app.route('/groups/<int:group_id>/expenses', methods=['POST'])
@login_required
def add_expense(group_id):
    """Add an expense to a group."""
    data = request.json

    if not data:
        return jsonify({'error': 'No data provided'}), 400
    if not data.get('description', '').strip():
        return jsonify({'error': 'Description is required'}), 400
    if not data.get('amount') or float(data['amount']) <= 0:
        return jsonify({'error': 'Valid amount is required'}), 400
    if not data.get('paid_by', '').strip():
        return jsonify({'error': 'paid_by is required'}), 400

    conn = get_db()
    c = conn.cursor()

    if not c.execute("SELECT id FROM groups WHERE id = ?", (group_id,)).fetchone():
        conn.close()
        return jsonify({'error': 'Group not found'}), 404

    # Check paid_by is a member
    member = c.execute(
        "SELECT id FROM members WHERE group_id = ? AND name = ?",
        (group_id, data['paid_by'].strip())
    ).fetchone()

    if not member:
        conn.close()
        return jsonify({'error': f'"{data["paid_by"]}" is not a member of this group'}), 400

    c.execute('''
        INSERT INTO expenses (group_id, description, amount, paid_by, category)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        group_id,
        data['description'].strip(),
        round(float(data['amount']), 2),
        data['paid_by'].strip(),
        data.get('category', 'Other').strip()
    ))
    expense_id = c.lastrowid

    # Auto-create equal splits for all members
    members = rows_to_list(c.execute(
        "SELECT name FROM members WHERE group_id = ?", (group_id,)
    ).fetchall())

    if members:
        share = round(float(data['amount']) / len(members), 2)
        for m in members:
            c.execute(
                "INSERT INTO expense_splits (expense_id, member_name, share) VALUES (?, ?, ?)",
                (expense_id, m['name'], share)
            )

    conn.commit()

    expense = row_to_dict(c.execute(
        "SELECT * FROM expenses WHERE id = ?", (expense_id,)
    ).fetchone())
    conn.close()

    return jsonify(expense), 201


@app.route('/groups/<int:group_id>/expenses/<int:expense_id>', methods=['DELETE'])
@login_required
def delete_expense(group_id, expense_id):
    """Delete an expense."""
    conn = get_db()
    c = conn.cursor()

    expense = c.execute(
        "SELECT * FROM expenses WHERE id = ? AND group_id = ?", (expense_id, group_id)
    ).fetchone()

    if not expense:
        conn.close()
        return jsonify({'error': 'Expense not found'}), 404

    c.execute("DELETE FROM expenses WHERE id = ?", (expense_id,))
    conn.commit()
    conn.close()

    return jsonify({'message': f'Expense "{expense["description"]}" deleted'}), 200


# ══════════════════════════════════════════
#  ROUTES — BALANCES & SETTLEMENTS
# ══════════════════════════════════════════

@app.route('/groups/<int:group_id>/balances', methods=['GET'])
@login_required
def get_balances(group_id):
    """Get net balance for each member."""
    conn = get_db()
    c = conn.cursor()
    if not c.execute("SELECT id FROM groups WHERE id = ?", (group_id,)).fetchone():
        conn.close()
        return jsonify({'error': 'Group not found'}), 404
    conn.close()

    balances = compute_balances(group_id)
    return jsonify({
        'group_id': group_id,
        'balances': balances,
        'settlements': compute_settlements(group_id)
    }), 200


@app.route('/groups/<int:group_id>/settle', methods=['POST'])
@login_required
def settle_up(group_id):
    """Mark a settlement as paid (record a repayment expense)."""
    data = request.json

    if not data or not data.get('from') or not data.get('to') or not data.get('amount'):
        return jsonify({'error': 'from, to, and amount are required'}), 400

    conn = get_db()
    c = conn.cursor()

    if not c.execute("SELECT id FROM groups WHERE id = ?", (group_id,)).fetchone():
        conn.close()
        return jsonify({'error': 'Group not found'}), 404

    # Record settlement as a special expense
    c.execute('''
        INSERT INTO expenses (group_id, description, amount, paid_by, category)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        group_id,
        f"Settlement: {data['from']} → {data['to']}",
        round(float(data['amount']), 2),
        data['from'],
        '✅ Settlement'
    ))
    conn.commit()
    conn.close()

    return jsonify({
        'message': f"Settlement recorded: {data['from']} paid {data['to']} ₹{data['amount']}",
        'balances': compute_balances(group_id),
        'settlements': compute_settlements(group_id)
    }), 200


# ══════════════════════════════════════════
#  ROUTES — SUMMARY / STATS
# ══════════════════════════════════════════

@app.route('/stats', methods=['GET'])
@login_required
def get_stats():
    """Get overall app statistics for current user."""
    user_id = session['user_id']
    
    conn = get_db()
    c = conn.cursor()

    # Get user's groups
    user_groups = [row[0] for row in c.execute('''
        SELECT DISTINCT g.id FROM groups g
        LEFT JOIN group_members gm ON g.id = gm.group_id
        WHERE g.created_by = ? OR gm.user_id = ?
    ''', (user_id, user_id)).fetchall()]

    if not user_groups:
        conn.close()
        return jsonify({
            'total_groups': 0,
            'total_members': 0,
            'total_expenses': 0,
            'total_amount': 0,
            'categories': [],
            'top_group': None
        }), 200

    group_ids = ','.join('?' * len(user_groups))
    
    total_groups = len(user_groups)
    total_members = c.execute(
        f"SELECT COUNT(DISTINCT name) FROM members WHERE group_id IN ({group_ids})",
        user_groups
    ).fetchone()[0]
    total_expenses = c.execute(
        f"SELECT COUNT(*) FROM expenses WHERE group_id IN ({group_ids})",
        user_groups
    ).fetchone()[0]
    total_amount = c.execute(
        f"SELECT COALESCE(SUM(amount), 0) FROM expenses WHERE group_id IN ({group_ids}) AND category != '✅ Settlement'",
        user_groups
    ).fetchone()[0]

    # Category breakdown
    categories = rows_to_list(c.execute(f'''
        SELECT category, COUNT(*) as count, SUM(amount) as total
        FROM expenses
        WHERE group_id IN ({group_ids}) AND category != '✅ Settlement'
        GROUP BY category
        ORDER BY total DESC
    ''', user_groups).fetchall())

    # Most active group
    top_group = row_to_dict(c.execute(f'''
        SELECT g.name, COUNT(e.id) as expense_count, COALESCE(SUM(e.amount), 0) as total
        FROM groups g
        LEFT JOIN expenses e ON g.id = e.group_id
        WHERE g.id IN ({group_ids})
        GROUP BY g.id
        ORDER BY total DESC
        LIMIT 1
    ''', user_groups).fetchone())

    conn.close()

    return jsonify({
        'total_groups':   total_groups,
        'total_members':  total_members,
        'total_expenses': total_expenses,
        'total_amount':   round(total_amount, 2),
        'categories':     categories,
        'top_group':      top_group
    }), 200


# ══════════════════════════════════════════
#  ERROR HANDLERS
# ══════════════════════════════════════════

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Route not found'}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'error': 'Method not allowed'}), 405

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error', 'details': str(e)}), 500


# ══════════════════════════════════════════
#  START
# ══════════════════════════════════════════

if __name__ == '__main__':
    init_db()
    print("🚀 SplitPay backend running on http://127.0.0.1:5000")
    print("\n📄 HTML Pages:")
    print("  GET    /                    (login.html)")
    print("  GET    /login.html")
    print("  GET    /dashboard.html")
    print("  GET    /groups.html")
    print("  GET    /settings.html")
    print("\n🔐 Authentication Endpoints:")
    print("  POST   /auth/register")
    print("  POST   /auth/login")
    print("  POST   /auth/logout")
    print("  GET    /auth/me")
    print("  GET    /auth/check")
    print("\n📋 API Endpoints:")
    print("  GET    /stats")
    print("  GET    /groups")
    print("  POST   /groups")
    print("  GET    /groups/<id>")
    print("  PUT    /groups/<id>")
    print("  DELETE /groups/<id>")
    print("  GET    /groups/<id>/members")
    print("  POST   /groups/<id>/members")
    print("  DELETE /groups/<id>/members/<member_id>")
    print("  GET    /groups/<id>/expenses")
    print("  POST   /groups/<id>/expenses")
    print("  DELETE /groups/<id>/expenses/<expense_id>")
    print("  GET    /groups/<id>/balances")
    print("  POST   /groups/<id>/settle")
    app.run(debug=True, port=5000)