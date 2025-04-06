from flask import Flask, request, jsonify
import hashlib

# Inicializamos la aplicación Flask
app = Flask(__name__)

# Diccionario para simular una base de datos de usuarios (solo para desarrollo)
# En una aplicación real, usaríamos una base de datos.
usuarios = {}

# Función para hashear la contraseña utilizando SHA-256
# Esto mejora la seguridad al no almacenar las contraseñas en texto plano.
def hashear_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Definimos la ruta /registro que acepta peticiones POST
@app.route('/registro', methods=['POST'])
def registrar_usuario():
    """
    Endpoint para registrar un nuevo usuario.
    Recibe 'usuario' y 'password' en el cuerpo de la petición (JSON).
    Si el usuario ya existe, devuelve un error.
    Si el usuario no existe, lo registra y devuelve un mensaje de éxito.
    """
    # Obtenemos los datos JSON de la petición
    data = request.get_json()

    # Verificamos si se recibieron datos y si contienen los campos 'usuario' y 'password'
    if not data or 'usuario' not in data or 'password' not in data:
        return jsonify({"error": "Faltan los campos 'usuario' o 'password'."}), 400

    usuario = data['usuario']
    password = data['password']

    # Verificamos si el usuario ya existe en nuestra "base de datos" simulada
    if usuario in usuarios:
        return jsonify({"error": "El usuario ya existe."}), 409

    # Hasheamos la contraseña antes de almacenarla
    password_hasheada = hashear_password(password)
    usuarios[usuario] = {"password": password_hasheada}

    # Devolvemos un mensaje de éxito con código de estado 201 (Creado)
    return jsonify({"mensaje": f"Usuario '{usuario}' registrado exitosamente."}), 201

# Definimos la ruta /login que acepta peticiones POST
@app.route('/login', methods=['POST'])
def iniciar_sesion():
    """
    Endpoint para iniciar sesión.
    Recibe 'usuario' y 'password' en el cuerpo de la petición (JSON).
    Verifica si el usuario existe y si la contraseña coincide (hasheada).
    Devuelve un mensaje de autenticación exitosa o un error.
    """
    # Obtenemos los datos JSON de la petición
    data = request.get_json()

    # Verificamos si se recibieron datos y si contienen los campos 'usuario' y 'password'
    if not data or 'usuario' not in data or 'password' not in data:
        return jsonify({"error": "Faltan los campos 'usuario' o 'password'."}), 400

    usuario = data['usuario']
    password = data['password']
    password_hasheada = hashear_password(password)

    # Verificamos si el usuario existe y si la contraseña hasheada coincide
    if usuario in usuarios and usuarios[usuario]['password'] == password_hasheada:
        # Autenticación exitosa, devolvemos un mensaje con código de estado 200 (OK)
        return jsonify({"mensaje": "Autenticación satisfactoria."}), 200
    else:
        # Error en la autenticación, devolvemos un mensaje con código de estado 401 (No autorizado)
        return jsonify({"error": "Error en la autenticación: usuario o contraseña incorrectos."}), 401

# Este bloque asegura que la aplicación se ejecute solo si el script es ejecutado directamente
if __name__ == '__main__':
    # Iniciamos el servidor de desarrollo de Flask en el puerto 5000
    # debug=True activa el modo de depuración, útil durante el desarrollo
    app.run(debug=True)