CREATE TABLE dbuserpasswordresettoken (domain varchar(255), userid varchar(255), token varchar(255), expiredate datetime);

CREATE TABLE dbuserprofile
(
    Domain VARCHAR(64) NOT NULL,
    UserId VARCHAR(64) NOT NULL,
    GivenName VARCHAR(255),
    Surname VARCHAR(255),
    Email VARCHAR(255),
    Department VARCHAR(255)
);

CREATE TABLE dbuserattributes
(
    Domain VARCHAR(64) NOT NULL,
    UserId VARCHAR(64) NOT NULL,
    Name VARCHAR(255),
    Value VARCHAR(255)
);