import os
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import bcrypt
import pandas as pd
import datetime
import secrets
import string
import MySQLdb
from decouple import config
from enuns.typeEnum import EnrollmentType

# Conexão com o banco de dados
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


def ISignIn():
    window = tk.Tk()
    window.title("Login")

    # create_user(window, 'admin', 'admin', 0,
    #             generate_access_token(), create_entity('unasp'))
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

    button_login = ttk.Button(frame, text="Login", command=lambda: auth_user(
        window, entry_accessToken.get(), entry_password.get()))
    button_login.pack()

    window.mainloop()

# Função para criar usuário


def create_user(window, peopleName, password, user_type, access_token, idEntity, is_admin=True):
    cursor = db.cursor()
    if is_admin:
        cursor.execute(
            "SELECT * FROM people p INNER JOIN enrollment e ON e.idPeople = p.id WHERE peopleName = %s AND p.accessToken = %s",
            (peopleName, access_token)
        )
        existing_user = cursor.fetchone()

        if existing_user:
            print("Usuário já existe. Não é possível criar o usuário.")
            return

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    cursor.execute(
        "INSERT INTO people (peopleName, password, accessToken) VALUES (%s, %s, %s)",
        (peopleName, hashed_password, access_token)
    )
    db.commit()

    cursor.execute("SELECT LAST_INSERT_ID()")
    user_id = cursor.fetchone()[0]

    cursor.execute(
        "INSERT INTO enrollment (idPeople, idEntity, type) VALUES (%s, %s, %s)",
        (user_id, idEntity, user_type)
    )
    db.commit()
    messagebox.showinfo("Login", "Usuário criado com sucesso!")
    window.destroy()

# Função para criar entidade


def create_entity(entityName, is_admin=True):
    cursor = db.cursor()

    if is_admin:
        cursor.execute(
            "SELECT * FROM entity WHERE entityName = %s", (entityName,))
        existing_entity = cursor.fetchone()

        if existing_entity:
            print("Entidade já existe. Não é possível criar a entidade.")
            return

    cursor.execute(
        "INSERT INTO entity (entityName) VALUES (%s)", (entityName,))
    db.commit()

    cursor.execute("SELECT LAST_INSERT_ID()")
    entity_id = cursor.fetchone()[0]

    return entity_id

# Função para autenticar o usuário


def auth_user(window, access_token, password):
    cursor = db.cursor()
    cursor.execute(
        "SELECT p.id, password, e.id, type FROM people p INNER JOIN enrollment e on p.id = e.idPeople WHERE p.accessToken = %s", (access_token,))
    result = cursor.fetchone()
    if result is not None:
        if bcrypt.checkpw(password.encode("utf-8"), result[1].encode("utf-8")):
            messagebox.showinfo("Login", "Login bem-sucedido!")
            window.destroy()
            if result[3] == EnrollmentType.isAdmin.value:
                show_dashboard(result[0], result[3], result[2])
            elif result[3] == EnrollmentType.isEmployee.value:
                show_employee_dashboard(result[0], result[3], result[2])
            elif result[3] == EnrollmentType.isManager.value:
                show_manager_dashboard(result[0], result[3], result[2])
        else:
            messagebox.showerror("Login", "Senha incorreta!")
    else:
        messagebox.showerror("Login", "Usuário não encontrado.")

# Função para obter registros de ponto


def get_people_clock_in():
    cursor = db.cursor()
    cursor.execute(
        "SELECT p.peopleName, c.date FROM people p INNER JOIN enrollment e ON e.idPeople = p.id INNER JOIN clockIn c ON c.idEnrollment = e.id;")
    people = cursor.fetchall()
    return people


def get_people():
    cursor = db.cursor()
    cursor.execute(
        "SELECT p.peopleName, p.id FROM people p INNER JOIN enrollment e ON e.idPeople = p.id")
    people = cursor.fetchall()
    return people
# Função para gerar um relatório de ponto


def generate_attendance_report(user_id, user_type):
    if user_type not in [EnrollmentType.isManager.value, EnrollmentType.isAdmin.value]:
        messagebox.showerror("Permissão Negada",
                             "Você não tem permissão para gerar relatórios.")
        return

    cursor = db.cursor()
    if user_type == EnrollmentType.isAdmin.value:
        cursor.execute(
            "SELECT p.peopleName, c.date FROM people p INNER JOIN enrollment e ON e.idPeople = p.id INNER JOIN clockIn c ON c.idEnrollment = e.id;")
    elif user_type == EnrollmentType.isManager.value:
        cursor.execute(
            "SELECT p.peopleName, c.date FROM people p INNER JOIN enrollment e ON e.idPeople = p.id INNER JOIN clockIn c ON c.idEnrollment = e.id WHERE e.idEntity IN (SELECT idEntity FROM enrollment WHERE idPeople = %s);",
            (user_id,)
        )

    attendance_records = cursor.fetchall()

    if attendance_records:
        df = pd.DataFrame(attendance_records, columns=[
                          'Funcionário', 'Data/Hora'])
        filename = "attendance_report.xlsx"
        df.to_excel(filename, index=False)
        messagebox.showinfo(
            "Relatório Gerado", f"Relatório de ponto gerado com sucesso em {filename}.")
    else:
        messagebox.showinfo(
            "Relatório Vazio", "Nenhum registro de ponto encontrado para gerar o relatório.")

# Função para registrar ponto


def clock_in(enrollment_id):
    cursor = db.cursor()
    current_datetime = datetime.datetime.now()
    date = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO clockIn (idEnrollment, date) VALUES (%s, %s)",
        (enrollment_id, date)
    )
    db.commit()
    messagebox.showinfo("Ponto Registrado", "Ponto registrado com sucesso!")

# Função para exportar dados


def export_data(people):
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

# Função para exibir o painel de controle


def show_dashboard(user_id, user_type, enrollment_id):
    window = tk.Tk()
    window.title("Dashboard")

    style = ttk.Style()
    style.configure("TLabel", font=("Arial", 16))

    frame = ttk.Frame(window, padding=40)
    frame.pack()

    label_dashboard = ttk.Label(frame, text="Bem-vindo ao Clock-In!")
    label_dashboard.pack()

    if user_type == EnrollmentType.isAdmin.value:
        peopleCl = get_people_clock_in()
        if peopleCl:
            label_people = ttk.Label(
                frame, text="Usuários que bateram o ponto:")
            label_people.pack()

            for user_info in peopleCl:
                user_id = user_info[0]
                # Display user information
                label_user = ttk.Label(frame, text=f"User Name: {user_id}")
                label_user.pack(side=tk.LEFT)
        else:
            label_no_people = ttk.Label(
                frame, text="Nenhum usuário bateu o ponto.")
            label_no_people.pack()
        peopleEn = get_people()
        if peopleEn:
            label_people = ttk.Label(
                frame, text="Todos os contratos de usuários:")
            label_people.pack()
            for useren_info in peopleEn:
                useren_name = useren_info[0]
                useren_id = useren_info[1]
                # Display user information
                label_user = ttk.Label(frame, text=f"User Name: {useren_name}")
                label_user.pack(side=tk.LEFT)

                button_edit = ttk.Button(
                    frame, text="Editar", command=lambda useren_id=useren_id: edit_user(useren_id))
                button_edit.pack(side=tk.RIGHT)

                button_delete = ttk.Button(
                    frame, text="Excluir", command=lambda useren_id=useren_id: delete_user(useren_id))
                button_delete.pack(side=tk.RIGHT)

        button_generate_report = ttk.Button(
            frame, text="Gerar Relatório", command=lambda: generate_attendance_report(user_type))
        button_generate_report.pack()

    button_clock_in = ttk.Button(
        window, text="Criar novo usuário", command=lambda: create_user_interface(window, user_type))
    button_clock_in.pack()

    button_clock_in = ttk.Button(
        window, text="Criar nova entidade", command=lambda: create_entity_interface(window))
    button_clock_in.pack()

    window.mainloop()

# Function to edit a user


def edit_user(user_id):
    window_edit_user = tk.Tk()
    window_edit_user.title("Editar Usuário")

    style = ttk.Style()
    style.configure("TLabel", font=("Arial", 12))
    style.configure("TEntry", font=("Arial", 12))
    style.configure("TButton", font=("Arial", 12))

    frame = ttk.Frame(window_edit_user, padding=20)
    frame.pack()

    label_peopleName = ttk.Label(frame, text="Novo Nome do Usuário:")
    label_peopleName.pack()

    entry_peopleName = ttk.Entry(frame)
    entry_peopleName.pack()

    label_password = ttk.Label(frame, text="Nova Senha:")
    label_password.pack()

    entry_password = ttk.Entry(frame, show="*")
    entry_password.pack()

    label_accessToken = ttk.Label(frame, text="Novo Código de Acesso:")
    label_accessToken.pack()

    entry_accessToken = ttk.Entry(frame)
    entry_accessToken.pack()

    button_save_changes = ttk.Button(frame, text="Salvar Alterações", command=lambda: save_user_changes(
        window_edit_user, user_id, entry_peopleName.get(), entry_password.get(), entry_accessToken.get()))
    button_save_changes.pack()

    window_edit_user.mainloop()

# Function to save changes to a user


def save_user_changes(window_edit_user, user_id, new_peopleName, new_password, new_accessToken):
    cursor = db.cursor()
    hashed_password = bcrypt.hashpw(
        new_password.encode("utf-8"), bcrypt.gensalt())

    cursor.execute("UPDATE people SET peopleName=%s, password=%s, accessToken=%s WHERE id=%s",
                   (new_peopleName, hashed_password, new_accessToken, user_id))
    db.commit()

    messagebox.showinfo(
        "Usuário Editado", "As alterações no usuário foram salvas com sucesso!")
    window_edit_user.destroy()

# Function to delete a user


def delete_user(user_id):
    confirmation = messagebox.askyesno(
        "Confirmar Exclusão", "Tem certeza que deseja excluir este usuário?")
    if confirmation:
        cursor = db.cursor()
        cursor.execute(
            "DELETE FROM enrollment WHERE idPeople=%s", (user_id,))
        db.commit()

        cursor = db.cursor()
        cursor.execute("DELETE FROM people WHERE id=%s", (user_id,))
        db.commit()
        messagebox.showinfo("Usuário Excluído",
                            "Usuário excluído com sucesso!")


# Função para exibir o painel de controle do gestor


def show_manager_dashboard(user_id, user_type, enrollment_id):
    window = tk.Tk()
    window.title("Dashboard - Gestor")

    entities = get_manager_entities(user_id)
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

    button_clock_in = ttk.Button(
        window, text="Bater ponto", command=lambda: clock_in(enrollment_id))
    button_clock_in.pack()

    button_clock_in = ttk.Button(
        window, text="Criar novo usuário", command=lambda: create_user_interface(window, user_type))
    button_clock_in.pack()

    button_generate_report = ttk.Button(
        window, text="Gerar Relatório", command=lambda: generate_attendance_report(user_type))
    button_generate_report.pack()

    window.mainloop()
# Função para exibir o painel de controle do funcionário


def show_employee_dashboard(user_id, user_type, enrollment_id):
    window = tk.Tk()
    window.title("Dashboard - Funcionário")

    label_contract = ttk.Label(window, text="Selecione o contrato:")
    label_contract.pack()

    contracts = get_employee_contracts(user_id)
    combo_contract = ttk.Combobox(window, values=contracts)
    combo_contract.pack()

    button_clock_in = ttk.Button(
        window, text="Bater ponto", command=lambda: clock_in(combo_contract.get()))
    button_clock_in.pack()

    window.mainloop()

# Função para exibir o histórico de registro de ponto


def show_clock_in_history(user_id, user_type, enrollment_id):
    window = tk.Tk()
    window.title("Histórico de Registro de Ponto")

    style = ttk.Style()
    style.configure("TLabel", font=("Arial", 12))
    style.configure("TButton", font=("Arial", 12))

    frame = ttk.Frame(window, padding=20)
    frame.pack()

    label_history = ttk.Label(frame, text="Histórico de Registro de Ponto")
    label_history.pack()

    if user_type == EnrollmentType.isAdmin.value:
        cursor = db.cursor()
        cursor.execute(
            "SELECT p.peopleName, c.date FROM people p INNER JOIN enrollment e ON e.idPeople = p.id INNER JOIN clockIn c ON c.idEnrollment = e.id;")
        clock_in_records = cursor.fetchall()
    elif user_type == EnrollmentType.isManager.value:
        cursor = db.cursor()
        cursor.execute(
            "SELECT p.peopleName, c.date FROM people p INNER JOIN enrollment e ON e.idPeople = p.id INNER JOIN clockIn c ON c.idEnrollment = e.id WHERE e.idEntity IN (SELECT idEntity FROM manager_entity WHERE idPeople = %s);",
            (user_id,)
        )
        clock_in_records = cursor.fetchall()
    else:
        cursor = db.cursor()
        cursor.execute(
            "SELECT p.peopleName, c.date FROM people p INNER JOIN enrollment e ON e.idPeople = p.id INNER JOIN clockIn c ON c.idEnrollment = e.id WHERE e.idPeople = %s;",
            (user_id,)
        )
        clock_in_records = cursor.fetchall()

    if clock_in_records:
        for record in clock_in_records:
            label_record = ttk.Label(
                frame, text=f"Usuário: {record[0]}, Data/Hora: {record[1]}")
            label_record.pack()
    else:
        label_no_records = ttk.Label(
            frame, text="Nenhum registro de ponto encontrado.")
        label_no_records.pack()

    window.mainloop()

# Função para obter contratos de funcionários


def create_entity_interface(window):
    window.title("Criar Entidade")

    style = ttk.Style()
    style.configure("TLabel", font=("Arial", 12))
    style.configure("TEntry", font=("Arial", 12))
    style.configure("TButton", font=("Arial", 12))

    frame = ttk.Frame(window, padding=20)
    frame.pack()

    label_entityName = ttk.Label(frame, text="Nome da Entidade:")
    label_entityName.pack()

    entry_entityName = ttk.Entry(frame)
    entry_entityName.pack()

    button_create_entity = ttk.Button(
        frame, text="Criar Entidade", command=lambda: create_entity(entry_entityName.get()))
    button_create_entity.pack()

    window.mainloop()

# Função para criar um usuário como admin através da interface gráfica


def create_user_interface(window, user_type):
    window.title("Criar Usuário")

    style = ttk.Style()
    style.configure("TLabel", font=("Arial", 12))
    style.configure("TEntry", font=("Arial", 12))
    style.configure("TButton", font=("Arial", 12))

    frame = ttk.Frame(window, padding=20)
    frame.pack()

    label_peopleName = ttk.Label(frame, text="Nome do Usuário:")
    label_peopleName.pack()

    entry_peopleName = ttk.Entry(frame)
    entry_peopleName.pack()

    label_password = ttk.Label(frame, text="Senha:")
    label_password.pack()

    entry_password = ttk.Entry(frame, show="*")
    entry_password.pack()

    label_entityName = ttk.Label(frame, text="Entidade:")
    label_entityName.pack()

    entities = get_all_entities()

    combo_entityName = ttk.Combobox(
        frame, values=[entity[0] for entity in entities], state="readonly")
    combo_entityName.pack()

    label_userType = ttk.Label(frame, text="Tipo de Usuário:")
    label_userType.pack()

    user_types = get_all_user_types(user_type)
    combo_userType = ttk.Combobox(frame, values=user_types, state="readonly")
    combo_userType.pack()

    button_create_user = ttk.Button(frame, text="Criar Usuário", command=lambda: create_user(window,
                                                                                             entry_peopleName.get(), entry_password.get(), combo_userType.get(), generate_access_token(), combo_entityName.get()))
    button_create_user.pack()

    window.mainloop()


def get_all_entities():
    cursor = db.cursor()
    cursor.execute("SELECT id, entityName FROM entity")
    entities = cursor.fetchall()
    return entities


def get_all_user_types(user_type):
    if user_type != EnrollmentType.isAdmin.value:
        return [et.value for et in EnrollmentType if et != EnrollmentType.isAdmin]
    else:
        return [et.value for et in EnrollmentType]


def get_employee_contracts(user_id):
    cursor = db.cursor()
    cursor.execute(
        "SELECT id FROM enrollment WHERE idPeople = %s", (user_id,))
    contracts = cursor.fetchall()
    return [contract[0] for contract in contracts]

# Função para obter entidades gerenciadas pelo gestor


def get_manager_entities(user_id):
    cursor = db.cursor()
    cursor.execute(
        "SELECT entityName FROM entity e INNER JOIN enrollment en ON e.id = en.idEntity WHERE en.idPeople = %s", (user_id,))
    entities = cursor.fetchall()
    return [entity[0] for entity in entities]

# Função para gerar um código de acesso aleatório


def generate_access_token():
    token_length = 32
    token_characters = string.ascii_letters + string.digits
    token = ''.join(secrets.choice(token_characters)
                    for _ in range(token_length))
    return token


# Chamada para iniciar o programa
ISignIn()
