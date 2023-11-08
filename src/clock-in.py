import secrets
import string
import MySQLdb
import os
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import bcrypt
import pandas as pd
import openpyxl
from decouple import config
from enuns.typeEnum import EnrollmentType

project_dir = os.path.dirname(os.path.abspath(__file__))
cert_path = os.path.join(project_dir, "..", "ssl", "cacert.pem")

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


def createUser(peopleName, password, user_type, access_token, idEntity, is_admin=False):
    cursor = db.cursor()

    if is_admin:
        cursor.execute(
            "SELECT * FROM people p INNER JOIN enrollment e on e.idPeople = p.id WHERE peopleName = %s AND p.accessToken = %s",
            (peopleName, access_token)
        )
        existing_user = cursor.fetchone()

        if existing_user:
            print("Usuário já existe. Não é possível criar o usuário.")
            return

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    user_type_enum = EnrollmentType(user_type).name

    cursor.execute(
        "INSERT INTO people (peopleName, password, accessToken) VALUES (%s, %s, %s)",
        (peopleName, hashed_password, access_token)
    )
    db.commit()

    cursor.execute("SELECT LAST_INSERT_ID()")
    user_id = cursor.fetchone()[0]

    cursor.execute(
        "INSERT INTO enrollment (idPeople, idEntity, type) VALUES (%s, %s, %s)",
        (user_id, idEntity, user_type_enum)
    )
    db.commit()


def authUser(window, access_token, password):
    cursor = db.cursor()

    cursor.execute(
        "SELECT id, password, accessToken FROM people WHERE accessToken = %s", (access_token))
    result = cursor.fetchone()

    if result is not None:
        if bcrypt.checkpw(password.encode("utf-8"), result[2].encode("utf-8")):
            messagebox.showinfo("Login", "Login bem-sucedido!")
            window.destroy()

            if result[1] == 0:
                showDashboard(result[0], result[1], result[3])
            elif result[1] == 1:
                showEmployeeDashboard(
                    window, result[0], result[1], result[3])
            elif result[1] == 2:
                showManagerDashboard(
                    window, result[0], result[1], result[3])
        else:
            messagebox.showerror("Login", "Senha incorreta!")
    else:
        messagebox.showerror("Login", "Usuário não encontrado.")


def ISignIn():
    window = tk.Tk()
    window.title("Login")

    style = ttk.Style()
    style.configure("TLabel", font=("Arial", 12))
    style.configure("TEntry", font=("Arial", 12))
    style.configure("TButton", font=("Arial", 12))

    frame = ttk.Frame(window, padding=20)
    frame.pack()

    label_accessToken = ttk.Label(frame, text="Código de acesso:")
    label_accessToken.pack()

    entry_accessToken = ttk.Entry(frame)
    entry_accessToken.pack()

    label_password = ttk.Label(frame, text="Senha:")
    label_password.pack()

    entry_password = ttk.Entry(frame, show="*")
    entry_password.pack()

    button_login = ttk.Button(frame, text="Login", command=lambda: authUser(
        window, entry_accessToken.get(), entry_password.get()))
    button_login.pack()

    window.mainloop()


def ISignUp():
    window = tk.Tk()
    window.title("Cadastro")

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


def showDashboard(user_id, user_type, access_token):
    window = tk.Tk()
    window.title("Dashboard")

    style = ttk.Style()
    style.configure("TLabel", font=("Arial", 16))

    frame = ttk.Frame(window, padding=40)
    frame.pack()

    label_dashboard = ttk.Label(frame, text="Bem-vindo ao Clock-In!")
    label_dashboard.pack()

    if user_type == 1:
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


def getpeopleClockIn():
    cursor = db.cursor()
    cursor.execute(
        "SELECT u.peopleName, c.date FROM people u INNER JOIN clockIn c ON u.id = c.idPeople")
    people = cursor.fetchall()
    return people


def clockIn(user_id, date, justification=None):
    cursor = db.cursor()

    cursor.execute(
        "INSERT INTO clockIn (idEnrollment, date, justification) VALUES (%s, %s, %s)",
        (user_id, date, justification)
    )
    db.commit()
    messagebox.showinfo("Ponto Registrado", "Ponto registrado com sucesso!")


def exportData(people):
    if people:
        data = {
            "Usuários que bateram o ponto": [user[0] for user in people],
            "Data": [user[1] for user in people]
        }
        df = pd.DataFrame(data)

        filename = "data.xlsx"
        df.to_excel(filename, index=False)
        messagebox.showinfo(
            "Exportar Dados", f"Dados exportados para o arquivo {filename}!")
    else:
        messagebox.showinfo("Exportar Dados", "Nenhum dado para exportar.")


def showEmployeeDashboard(window, user_id, user_type, access_token):
    window.title("Dashboard - Funcionário")

    label_contract = ttk.Label(window, text="Selecione o contrato:")
    label_contract.pack()

    contracts = getEmployeeContracts(user_id)
    combo_contract = ttk.Combobox(window, values=contracts)
    combo_contract.pack()

    button_clock_in = ttk.Button(
        window, text="Bater ponto", command=lambda: clockIn(user_id, combo_contract.get()))
    button_clock_in.pack()

    window.mainloop()


def getEmployeeContracts(user_id):
    cursor = db.cursor()
    cursor.execute(
        "SELECT contractName FROM enrollment WHERE idPeople = %s", (user_id,))
    contracts = cursor.fetchall()
    return [contract[0] for contract in contracts]


def showManagerDashboard(window, user_id, user_type, access_token):
    window.title("Dashboard - Gestor")

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


def getManagerEntities(user_id):
    cursor = db.cursor()
    cursor.execute(
        "SELECT entityName FROM entity e INNER JOIN manager_entity me ON e.id = me.idEntity WHERE me.idPeople = %s", (user_id,))
    entities = cursor.fetchall()
    return [entity[0] for entity in entities]


def generateAccessToken():
    token_length = 32
    token_characters = string.ascii_letters + string.digits
    token = ''.join(secrets.choice(token_characters)
                    for _ in range(token_length))
    return token


def createEntity(entityName, is_admin=False):
    cursor = db.cursor()

    if is_admin:
        # Verifica se a entidade já existe no banco de dados
        cursor.execute(
            "SELECT * FROM entity WHERE entityName = %s", (entityName,))
        existing_entity = cursor.fetchone()

        if existing_entity:
            print("Entidade já existe. Não é possível criar a entidade.")
            return

    cursor.execute(
        "INSERT INTO entity (entityName) VALUES (%s)", (entityName,))
    db.commit()

    # Obter o ID da entidade recém-criada
    cursor.execute("SELECT LAST_INSERT_ID()")
    entity_id = cursor.fetchone()[0]

    return entity_id


ISignIn()
createUser("admin", "admin", EnrollmentType.isAdmin,
           generateAccessToken(), createEntity('base'))
