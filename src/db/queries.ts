import type { User } from '../types';

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

export async function getUserByUsername(db: D1Database, username: string): Promise<User | null> {
  return db
    .prepare('SELECT * FROM users WHERE username = ?')
    .bind(username)
    .first<User>();
}

export async function getUserByEmail(db: D1Database, email: string): Promise<User | null> {
  return db
    .prepare('SELECT * FROM users WHERE email = ?')
    .bind(email)
    .first<User>();
}

export async function getUserById(db: D1Database, id: string): Promise<User | null> {
  return db.prepare('SELECT * FROM users WHERE id = ?').bind(id).first<User>();
}

export async function createUser(
  db: D1Database,
  user: Pick<User, 'id' | 'username' | 'email' | 'password_hash'>,
): Promise<void> {
  await db
    .prepare('INSERT INTO users (id, username, email, password_hash) VALUES (?, ?, ?, ?)')
    .bind(user.id, user.username, user.email, user.password_hash)
    .run();

  // Assign the default "user" role
  const roleRow = await db
    .prepare("SELECT id FROM roles WHERE name = 'user'")
    .first<{ id: string }>();

  if (roleRow) {
    await db
      .prepare('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)')
      .bind(user.id, roleRow.id)
      .run();
  }
}

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

export async function getUserRoles(db: D1Database, userId: string): Promise<string[]> {
  const result = await db
    .prepare(
      `SELECT r.name
       FROM roles r
       JOIN user_roles ur ON r.id = ur.role_id
       WHERE ur.user_id = ?`,
    )
    .bind(userId)
    .all<{ name: string }>();

  return result.results.map(r => r.name);
}
