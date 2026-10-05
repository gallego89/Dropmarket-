"""Cria ou redefine o usuário dono da loja.
Uso:  python create_user.py seu@email.com [senha]
Sem senha, uma senha forte é gerada e mostrada uma única vez."""
import secrets, sys
from werkzeug.security import generate_password_hash
import app as A

if len(sys.argv) < 2:
    sys.exit(__doc__)
email = sys.argv[1].strip().lower()
senha = sys.argv[2] if len(sys.argv) > 2 else "".join(secrets.choice("abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(16))
if len(senha) < 8:
    sys.exit("A senha precisa ter ao menos 8 caracteres.")
with A.app.app_context():
    db = A.db()
    cur = db.execute("SELECT id,email FROM users").fetchall()
    if cur and cur[0]["email"] != email:
        sys.exit(f"Já existe um dono ({cur[0]['email']}). Use o mesmo e-mail para redefinir a senha.")
    h = generate_password_hash(senha)
    if cur:
        db.execute("UPDATE users SET pass_hash=? WHERE id=?", (h, cur[0]["id"]))
    else:
        db.execute("INSERT INTO users(email,pass_hash) VALUES(?,?)", (email, h))
    db.commit()
print(f"E-mail: {email}\nSenha:  {senha}")
