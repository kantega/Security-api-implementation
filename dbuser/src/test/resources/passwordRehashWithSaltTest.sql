CREATE TABLE dbuserpassword
(
    Domain VARCHAR(64),
    UserId VARCHAR(64),
    Password VARCHAR(4096)
);

INSERT INTO dbuserpassword (Domain, UserId, Password) VALUES('my domain', 'jason', '$1$ySaku907$ZWT.buQ7nDHn7avJqlK420');