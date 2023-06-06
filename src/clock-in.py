import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import bcrypt
import mysql.connector
from datetime import datetime
import pandas as pd

# Função para criar a tabela, se ainda não existir


def createTable():
    cursor = db.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) NOT NULL,
            password VARCHAR(255) NOT NULL,
            type INT(1) NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS clockIn (
            id INT AUTO_INCREMENT PRIMARY KEY,
            idUser INT NOT NULL,
            date VARCHAR(255) NOT NULL,
            FOREIGN KEY (idUser) REFERENCES users(id)
        )
    """)
    db.commit()

# Função para criar um novo usuário no banco de dados


def createUser(username, password, type):
    cursor = db.cursor()

    # Hash da password usando bcrypt
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    cursor.execute(
        "INSERT INTO users (username, password, type) VALUES (%s, %s, %s)", (username, hashed_password, type))
    db.commit()

# Função para verificar se as credenciais de login são válidas


def authUser(window, username, password):
    cursor = db.cursor()

    cursor.execute(
        "SELECT id, type, password FROM users WHERE username = %s", (username,))
    resultado = cursor.fetchone()

    if resultado is not None:
        # Verificar a password usando bcrypt
        if bcrypt.checkpw(password.encode("utf-8"), resultado[2].encode("utf-8")):
            messagebox.showinfo("Login", "Login bem-sucedido!")
            window.destroy()  # Fechar a janela de login
            # Passar o id e o tipo do usuário
            showDashboard(resultado[0], resultado[1])
        else:
            messagebox.showerror("Login", "Senha incorreta!")
    else:
        messagebox.showerror("Login", "Usuário não encontrado!")

# Função para criar a interface de login


def ISignIn():
    window = tk.Tk()
    window.title("Login")

    # Estilo dos widgets usando ttk
    style = ttk.Style()
    style.configure("TLabel", font=("Arial", 12))
    style.configure("TEntry", font=("Arial", 12))
    style.configure("TButton", font=("Arial", 12))

    frame = ttk.Frame(window, padding=20)
    frame.pack()

    label_username = ttk.Label(frame, text="Usuário:")
    label_username.pack()

    entry_username = ttk.Entry(frame)
    entry_username.pack()

    label_password = ttk.Label(frame, text="Senha:")
    label_password.pack()

    entry_password = ttk.Entry(frame, show="*")
    entry_password.pack()

    button_login = ttk.Button(frame, text="Login", command=lambda: authUser(window,
                                                                            entry_username.get(), entry_password.get()))
    button_login.pack()

    button_cadastrar = ttk.Button(frame, text="Novo por aqui? Cadastre-se!", command=lambda: [
                                  window.destroy(), ISignUp()])
    button_cadastrar.pack()

    window.mainloop()

# Função para criar a interface de cadastro


def ISignUp():
    window = tk.Tk()
    window.title("Cadastro")

    # Estilo dos widgets usando ttk
    style = ttk.Style()
    style.configure("TLabel", font=("Arial", 12))
    style.configure("TEntry", font=("Arial", 12))
    style.configure("TButton", font=("Arial", 12))

    frame = ttk.Frame(window, padding=20)
    frame.pack()

    label_username = ttk.Label(frame, text="Usuário:")
    label_username.pack()

    entry_username = ttk.Entry(frame)
    entry_username.pack()

    label_password = ttk.Label(frame, text="Senha:")
    label_password.pack()

    entry_password = ttk.Entry(frame, show="*")
    entry_password.pack()

    button_cadastrar = ttk.Button(frame, text="Cadastrar", command=lambda: [
                                  createUser(entry_username.get(), entry_password.get(), 0), window.destroy(), ISignIn()])
    button_cadastrar.pack()

    window.mainloop()

# Função para abrir o dashboard após o login


def showDashboard(user_id, user_type):
    window = tk.Tk()
    window.title("Dashboard")

    # Estilo dos widgets usando ttk
    style = ttk.Style()
    style.configure("TLabel", font=("Arial", 16))

    frame = ttk.Frame(window, padding=40)
    frame.pack()

    label_dashboard = ttk.Label(frame, text="Bem-vindo ao Clock-In!")
    label_dashboard.pack()

    if user_type == 1:  # Se o tipo de usuário for 1, exibir a lista de usuários que bateram o ponto
        users = getUsersClockIn()
        if users:
            label_users = ttk.Label(
                frame, text="Usuários que bateram o ponto:")
            label_users.pack()

            for user in users:
                label_user = ttk.Label(frame, text=user)
                label_user.pack()
        else:
            label_no_users = ttk.Label(
                frame, text="Nenhum usuário bateu o ponto.")
            label_no_users.pack()

        button_export = ttk.Button(
            frame, text="Exportar dados", command=lambda: exportData(users))
        button_export.pack()

    button_clock_in = ttk.Button(
        frame, text="Bater ponto", command=lambda: clockIn(user_id))
    button_clock_in.pack()

    window.mainloop()

# Função para obter a lista de usuários que bateram o ponto


def getUsersClockIn():
    cursor = db.cursor()
    cursor.execute(
        "SELECT u.username, c.date FROM users u INNER JOIN clockIn c ON u.id = c.idUser")
    users = cursor.fetchall()
    return users

# Função para registrar o ponto de um usuário


def clockIn(user_id):
    cursor = db.cursor()

    # Obter a data e hora atual
    now = datetime.now()
    date = now.strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        "INSERT INTO clockIn (idUser, date) VALUES (%s, %s)", (user_id, date))
    db.commit()

    messagebox.showinfo("Ponto Registrado", "Ponto registrado com sucesso!")

# Função para exportar os dados para uma planilha do Excel


def exportData(users):
    if users:
        # Criar um DataFrame do Pandas com os dados
        data = {
            "Usuários que bateram o ponto": [user[0] for user in users],
            "Data": [user[1] for user in users]
        }
        df = pd.DataFrame(data)

        # Salvar o DataFrame no arquivo Excel
        filename = "data.xlsx"
        df.to_excel(filename, index=False)
        messagebox.showinfo(
            "Exportar Dados", f"Dados exportados para o arquivo {filename}!")
    else:
        messagebox.showinfo("Exportar Dados", "Nenhum dado para exportar.")


# Conexão com o banco de dados MySQL
db = mysql.connector.connect(
    host='localhost',
    user='root',
    password='',
    database='ClockIn'
)
createTable()
createUser('admin', 'admin', 1)
ISignIn()
