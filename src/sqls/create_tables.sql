CREATE TABLE IF NOT EXISTS people (
    id INT AUTO_INCREMENT PRIMARY KEY,
    peopleName VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    accessToken NVARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS entity (
    id INT AUTO_INCREMENT PRIMARY KEY,
    entityName VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS enrollment (
    id INT AUTO_INCREMENT PRIMARY KEY,
    idPeople INT NOT NULL,
    idEntity INT NOT NULL,
    type ENUM('isAdmin', 'isManager', 'isEmployee') NOT NULL,
    FOREIGN KEY (idPeople) REFERENCES people(id) ON DELETE NO ACTION,
    FOREIGN KEY (idEntity) REFERENCES entity(id) ON DELETE NO ACTION
);


CREATE TABLE IF NOT EXISTS clockIn (
    id INT AUTO_INCREMENT PRIMARY KEY,
    idEnrollment INT NOT NULL,
    date VARCHAR(255) NOT NULL,
    FOREIGN KEY (idEnrollment) REFERENCES enrollment(id)
);
