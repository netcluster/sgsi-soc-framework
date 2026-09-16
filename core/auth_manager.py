# -*- coding: utf-8 -*-
"""
Módulo de Gestión de Autenticación, Usuarios y Control de Acceso basado en Roles (RBAC).
Framework SGSI & SOC (SERMIG 2026).
Seguridad de contraseñas con PBKDF2-HMAC-SHA256 y salt criptográfico (OWASP Standard).
"""

import os
import json
import hashlib
import binascii
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

class AuthManager:
    ROLES = ["Administrador", "Operador", "Visor"]

    def __init__(self, config_dir: str = None):
        if config_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.config_dir = os.path.join(base_dir, "config")
        else:
            self.config_dir = config_dir

        self.users_file = os.path.join(self.config_dir, "users.json")
        os.makedirs(self.config_dir, exist_ok=True)
        self._ensure_default_users()

    def _hash_password(self, password: str, salt_hex: str = None) -> Tuple[str, str]:
        """Genera hash seguro PBKDF2-HMAC-SHA256 con salt."""
        if salt_hex is None:
            salt = os.urandom(16)
            salt_hex = binascii.hexlify(salt).decode("ascii")
        else:
            salt = binascii.unhexlify(salt_hex.encode("ascii"))

        pwd_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations=100000
        )
        return binascii.hexlify(pwd_hash).decode("ascii"), salt_hex

    def _verify_password(self, password: str, hashed_pwd: str, salt_hex: str) -> bool:
        """Verifica una contraseña contra su hash y salt."""
        check_hash, _ = self._hash_password(password, salt_hex)
        return check_hash == hashed_pwd

    def _ensure_default_users(self):
        """Crea los usuarios iniciales si el archivo de usuarios no existe."""
        if not os.path.exists(self.users_file):
            initial_users = {}
            # 1. Admin
            h_admin, s_admin = self._hash_password("Admin@SERMIG2026")
            initial_users["admin"] = {
                "username": "admin",
                "full_name": "Administrador Principal CISO",
                "email": "ciso@serviciomigraciones.cl",
                "role": "Administrador",
                "password_hash": h_admin,
                "salt": s_admin,
                "active": True,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_login": "-"
            }
            # 2. Operador SOC
            h_op, s_op = self._hash_password("Operador@SERMIG2026")
            initial_users["operador"] = {
                "username": "operador",
                "full_name": "Analista de Operaciones SOC L1",
                "email": "soc.analista@serviciomigraciones.cl",
                "role": "Operador",
                "password_hash": h_op,
                "salt": s_op,
                "active": True,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_login": "-"
            }
            # 3. Visor Auditor
            h_vis, s_vis = self._hash_password("Visor@SERMIG2026")
            initial_users["visor"] = {
                "username": "visor",
                "full_name": "Auditor Interno / Dirección",
                "email": "auditoria@serviciomigraciones.cl",
                "role": "Visor",
                "password_hash": h_vis,
                "salt": s_vis,
                "active": True,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_login": "-"
            }
            self._save_users(initial_users)

    def _load_users(self) -> Dict[str, Any]:
        """Carga el diccionario de usuarios desde disco."""
        if not os.path.exists(self.users_file):
            self._ensure_default_users()
        try:
            with open(self.users_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_users(self, users: Dict[str, Any]) -> bool:
        """Guarda el diccionario de usuarios en disco."""
        try:
            with open(self.users_file, "w", encoding="utf-8") as f:
                json.dump(users, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"[ERROR AuthManager] No se pudo guardar users.json: {e}")
            return False

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Valida credenciales. Si es exitoso, retorna el perfil de usuario sin hashes sensibles."""
        if not username or not password:
            return None
        users = self._load_users()
        u_key = username.strip().lower()
        if u_key not in users:
            return None
        user_data = users[u_key]
        if not user_data.get("active", True):
            return None

        if self._verify_password(password, user_data.get("password_hash", ""), user_data.get("salt", "")):
            # Actualizar last_login
            user_data["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            users[u_key] = user_data
            self._save_users(users)

            return {
                "username": user_data.get("username"),
                "full_name": user_data.get("full_name"),
                "email": user_data.get("email"),
                "role": user_data.get("role", "Visor"),
                "last_login": user_data.get("last_login")
            }
        return None

    def get_all_users(self) -> List[Dict[str, Any]]:
        """Retorna lista de todos los usuarios registrados (sin hash ni salt)."""
        users = self._load_users()
        result = []
        for u in users.values():
            result.append({
                "username": u.get("username"),
                "full_name": u.get("full_name"),
                "email": u.get("email"),
                "role": u.get("role"),
                "active": u.get("active", True),
                "created_at": u.get("created_at", "-"),
                "last_login": u.get("last_login", "-")
            })
        return result

    def create_user(self, username: str, full_name: str, email: str, role: str, password: str) -> Tuple[bool, str]:
        """Crea un nuevo usuario."""
        u_key = username.strip().lower()
        if not u_key or len(u_key) < 3:
            return False, "El nombre de usuario debe tener al menos 3 caracteres."
        if not password or len(password) < 6:
            return False, "La contraseña debe tener al menos 6 caracteres."
        if role not in self.ROLES:
            return False, f"Rol no válido. Debe ser uno de: {', '.join(self.ROLES)}"

        users = self._load_users()
        if u_key in users:
            return False, f"El usuario '{username}' ya existe en el sistema."

        h_pwd, salt = self._hash_password(password)
        users[u_key] = {
            "username": username.strip(),
            "full_name": full_name.strip() or username.strip(),
            "email": email.strip() or "-",
            "role": role,
            "password_hash": h_pwd,
            "salt": salt,
            "active": True,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_login": "-"
        }
        if self._save_users(users):
            return True, f"Usuario '{username}' creado exitosamente con rol {role}."
        return False, "Error al guardar el usuario en la base de datos."

    def update_user(self, username: str, full_name: str, email: str, role: str, active: bool, new_password: str = None) -> Tuple[bool, str]:
        """Actualiza los datos de un usuario existente."""
        u_key = username.strip().lower()
        users = self._load_users()
        if u_key not in users:
            return False, f"El usuario '{username}' no existe."
        if role not in self.ROLES:
            return False, f"Rol no válido. Debe ser uno de: {', '.join(self.ROLES)}"

        user_data = users[u_key]
        user_data["full_name"] = full_name.strip() or user_data.get("full_name")
        user_data["email"] = email.strip() or user_data.get("email")
        user_data["role"] = role
        user_data["active"] = bool(active)

        if new_password and len(new_password) >= 6:
            h_pwd, salt = self._hash_password(new_password)
            user_data["password_hash"] = h_pwd
            user_data["salt"] = salt

        users[u_key] = user_data
        if self._save_users(users):
            return True, f"Usuario '{username}' actualizado correctamente."
        return False, "Error al guardar la actualización."

    def delete_user(self, username: str) -> Tuple[bool, str]:
        """Elimina un usuario (protege contra la eliminación del último Administrador)."""
        u_key = username.strip().lower()
        users = self._load_users()
        if u_key not in users:
            return False, f"El usuario '{username}' no existe."

        # Verificar si es el único Administrador
        admins = [u for u in users.values() if u.get("role") == "Administrador" and u.get("active", True)]
        if users[u_key].get("role") == "Administrador" and len(admins) <= 1:
            return False, "No se puede eliminar el único Administrador activo del sistema."

        del users[u_key]
        if self._save_users(users):
            return True, f"Usuario '{username}' eliminado correctamente."
        return False, "Error al eliminar usuario."
