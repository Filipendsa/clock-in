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
    KEY (idPeople),
    KEY (idEntity)
);


CREATE TABLE IF NOT EXISTS clockIn (
    id INT AUTO_INCREMENT PRIMARY KEY,
    idEnrollment INT NOT NULL,
    date VARCHAR(255) NOT NULL,
    KEY (idEnrollment)
);
