import MySQLdb
import os
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import bcrypt
from datetime import datetime
import pandas as pd
import secrets
import string
from decouple import config
from enuns.typeEnum import EnrollmentType

project_dir = os.path.dirname(os.path.abspath(__file__))
cert_path = os.path.join(project_dir, "..", "ssl", "cacert.pem")
sql_file = os.path.join(project_dir, "sqls", "create_tables.sql")

# Carrega as variáveis de ambiente do arquivo .env

db = MySQLdb.connect(
    host=config('DB_HOST'),
    user=config('DB_USERNAME'),
    passwd=config('DB_PASSWORD'),
    db=config('DB_NAME'),
    autocommit=True,
    ssl_mode="VERIFY_IDENTITY",
    ssl={
        "ca": cert_path
    }
)

# Função para criar a tabela, se ainda não existir


def createTable():
    with open(sql_file, 'r') as sql_script:
        cursor = db.cursor()
        for statement in sql_script.read().split(';'):
            cursor.execute(statement)


# Função para criar um novo usuário no banco de dados


def createUser(peopleName, password, user_type):
    cursor = db.cursor()

    # Verifica se o nome de usuário já existe no banco de dados
    cursor.execute("SELECT * FROM people WHERE peopleName = %s", (peopleName,))
    existing_user = cursor.fetchone()

    if existing_user:
        print("Nome de usuário já existe. Não é possível criar o usuário.")
        return

    # Gere um token de acesso (accessToken)
    access_token = generateAccessToken()

    # Hash da senha usando bcrypt
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    # Obtenha o valor ENUM correspondente ao tipo de usuário
    user_type_enum = EnrollmentType(user_type).name

    cursor.execute(
        "INSERT INTO people (peopleName, password, accessToken) VALUES (%s, %s, %s)",
        (peopleName, hashed_password, access_token)
    )
    db.commit()

    # Obtenha o ID do usuário recém-criado
    cursor.execute("SELECT LAST_INSERT_ID()")
    user_id = cursor.fetchone()[0]

    # Insira a entrada na tabela enrollment
    cursor.execute(
        "INSERT INTO enrollment (idPeople, idEntity, type) VALUES (%s, %s, %s)",
        (user_id, 0, user_type_enum)  # Use 0 como o ID da entidade por padrão
    )
    db.commit()
# Função para verificar se as credenciais de login são válidas


def authUser(window, peopleName, password):
    cursor = db.cursor()

    cursor.execute(
        "SELECT id, type, password, accessToken FROM people WHERE peopleName = %s", (peopleName,))
    result = cursor.fetchone()

    if result is not None:
        # Verificar a senha usando bcrypt
        if bcrypt.checkpw(password.encode("utf-8"), result[2].encode("utf-8")):
            messagebox.showinfo("Login", "Login bem-sucedido!")
            window.destroy()  # Fechar a janela de login
            # Passar o id e o tipo do usuário, bem como o accessToken
            if result[1] == 0:  # Admin
                showDashboard(result[0], result[1], result[3])
            elif result[1] == 1:  # Funcionário
                showEmployeeDashboard(
                    window, result[0], result[1], result[3])
            elif result[1] == 2:  # Gestor
                showManagerDashboard(
                    window, result[0], result[1], result[3])
        else:
            messagebox.showerror("Login", "Senha incorreta!")
    else:
        messagebox.showerror("Login", "Usuário não encontrado.")

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

    label_peopleName = ttk.Label(frame, text="Usuário:")
    label_peopleName.pack()

    entry_peopleName = ttk.Entry(frame)
    entry_peopleName.pack()

    label_password = ttk.Label(frame, text="Senha:")
    label_password.pack()

    entry_password = ttk.Entry(frame, show="*")
    entry_password.pack()

    button_login = ttk.Button(frame, text="Login", command=lambda: authUser(
        window, entry_peopleName.get(), entry_password.get()))
    button_login.pack()

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

    label_peopleName = ttk.Label(frame, text="Usuário:")
    label_peopleName.pack()

    entry_peopleName = ttk.Entry(frame)
    entry_peopleName.pack()

    label_password = ttk.Label(frame, text="Senha:")
    label_password.pack()

    entry_password = ttk.Entry(frame, show="*")
    entry_password.pack()

    button_cadastrar = ttk.Button(frame, text="Cadastrar", command=lambda: [
                                  createUser(entry_peopleName.get(), entry_password.get(), 0), window.destroy(), ISignIn()])
    button_cadastrar.pack()

    window.mainloop()

# Função para abrir o dashboard após o login


def showDashboard(user_id, user_type, access_token):
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
        people = getpeopleClockIn()
        if people:
            label_people = ttk.Label(
                frame, text="Usuários que bateram o ponto:")
            label_people.pack()

            for user in people:
                label_user = ttk.Label(frame, text=user)
                label_user.pack()
        else:
            label_no_people = ttk.Label(
                frame, text="Nenhum usuário bateu o ponto.")
            label_no_people.pack()

        button_export = ttk.Button(
            frame, text="Exportar dados", command=lambda: exportData(people))
        button_export.pack()

    button_clock_in = ttk.Button(
        frame, text="Bater ponto", command=lambda: clockIn(user_id))
    button_clock_in.pack()

    window.mainloop()

# Função para obter a lista de usuários que bateram o ponto


def getpeopleClockIn():
    cursor = db.cursor()
    cursor.execute(
        "SELECT u.peopleName, c.date FROM people u INNER JOIN clockIn c ON u.id = c.idPeople")
    people = cursor.fetchall()
    return people

# Função para registrar o ponto de um usuário


def clockIn(user_id):
    cursor = db.cursor()

    # Obter a data e hora atual
    now = datetime.now()
    date = now.strftime("%Y-%m-%d %H:%M:%S")

    # Inserir o registro do ponto
    cursor.execute(
        "INSERT INTO clockIn (idEnrollment, date) VALUES (%s, %s)", (user_id, date))
    db.commit()
    messagebox.showinfo("Ponto Registrado",
                        "Ponto registrado com sucesso!")

# Função para exportar os dados para uma planilha do Excel


def exportData(people):
    if people:
        # Criar um DataFrame do Pandas com os dados
        data = {
            "Usuários que bateram o ponto": [user[0] for user in people],
            "Data": [user[1] for user in people]
        }
        df = pd.DataFrame(data)

        # Salvar o DataFrame no arquivo Excel
        filename = "data.xlsx"
        df.to_excel(filename, index=False)
        messagebox.showinfo(
            "Exportar Dados", f"Dados exportados para o arquivo {filename}!")
    else:
        messagebox.showinfo("Exportar Dados", "Nenhum dado para exportar.")

# Função para abrir o dashboard após o login para funcionários


def showEmployeeDashboard(window, user_id, user_type, access_token):
    window.title("Dashboard - Funcionário")

    # Resto do código para a interface do funcionário

    # Adicione uma opção de seleção de contrato
    label_contract = ttk.Label(window, text="Selecione o contrato:")
    label_contract.pack()

    # Suponha que você tenha uma lista de contratos disponíveis para o funcionário
    contracts = getEmployeeContracts(user_id)
    combo_contract = ttk.Combobox(window, values=contracts)
    combo_contract.pack()

    # Botão para registrar o ponto no contrato selecionado
    button_clock_in = ttk.Button(
        window, text="Bater ponto", command=lambda: clockIn(user_id, combo_contract.get()))
    button_clock_in.pack()

    window.mainloop()

# Função para obter a lista de contratos disponíveis para um funcionário


def getEmployeeContracts(user_id):
    cursor = db.cursor()
    cursor.execute(
        "SELECT contractName FROM enrollment WHERE idPeople = %s", (user_id,))
    contracts = cursor.fetchall()
    return [contract[0] for contract in contracts]

# Função para abrir o dashboard após o login para gestores


def showManagerDashboard(window, user_id, user_type, access_token):
    window.title("Dashboard - Gestor")

    # Resto do código para a interface do gestor

    # Permita que o gestor visualize a entidade que ele gerencia
    entities = getManagerEntities(user_id)
    if entities:
        label_entities = ttk.Label(
            window, text="Entidades gerenciadas pelo gestor:")
        label_entities.pack()

        for entity in entities:
            label_entity = ttk.Label(window, text=entity)
            label_entity.pack()
    else:
        label_no_entities = ttk.Label(
            window, text="O gestor não gerencia nenhuma entidade.")
        label_no_entities.pack()

    window.mainloop()

# Função para obter a lista de entidades gerenciadas por um gestor


def getManagerEntities(user_id):
    cursor = db.cursor()
    cursor.execute(
        "SELECT entityName FROM entity e INNER JOIN manager_entity me ON e.id = me.idEntity WHERE me.idPeople = %s", (user_id,))
    entities = cursor.fetchall()
    return [entity[0] for entity in entities]

# Função para gerar um token de acesso


def generateAccessToken():
    # Tamanho desejado do token
    token_length = 32

    # Caracteres permitidos para o token (alfanuméricos)
    token_characters = string.ascii_letters + string.digits

    # Gera o token aleatório
    token = ''.join(secrets.choice(token_characters)
                    for _ in range(token_length))

    return token


# Chama a função createTable() para criar as tabelas no banco de dados
createTable()
# Chama a função ISignIn() para iniciar o aplicativo
# ISignIn()
