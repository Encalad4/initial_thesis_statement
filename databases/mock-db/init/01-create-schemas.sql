-- databases/mock-db/init/01-create-schemas.sql
-- Create IT department schema
CREATE SCHEMA IF NOT EXISTS it_department;

-- Create Finance department schema
CREATE SCHEMA IF NOT EXISTS finance_department;

-- Create employees table in IT schema
CREATE TABLE it_department.employees (
    employee_id SERIAL PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    department VARCHAR(20) DEFAULT 'IT',
    hire_date DATE DEFAULT CURRENT_DATE
);

-- Create employee_accounts table in IT schema
CREATE TABLE it_department.employee_accounts (
    account_id SERIAL PRIMARY KEY,
    employee_id INTEGER REFERENCES it_department.employees(employee_id),
    service_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    username VARCHAR(50),
    password VARCHAR(100) NOT NULL,  -- Plain text for testing only!
    created_date DATE DEFAULT CURRENT_DATE,
    UNIQUE(employee_id, service_name)
);

-- Create employees table in Finance schema
CREATE TABLE finance_department.employees (
    employee_id SERIAL PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    department VARCHAR(20) DEFAULT 'Finance',
    hire_date DATE DEFAULT CURRENT_DATE
);

-- Create employee_accounts table in Finance schema
CREATE TABLE finance_department.employee_accounts (
    account_id SERIAL PRIMARY KEY,
    employee_id INTEGER REFERENCES finance_department.employees(employee_id),
    service_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    username VARCHAR(50),
    password VARCHAR(100) NOT NULL,  -- Plain text for testing only!
    created_date DATE DEFAULT CURRENT_DATE,
    UNIQUE(employee_id, service_name)
);