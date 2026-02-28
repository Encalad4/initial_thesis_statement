-- databases/mock-db/init/02-insert-data.sql
-- Insert IT department employees
INSERT INTO it_department.employees (first_name, last_name, email, hire_date) VALUES
    ('John', 'Smith', 'john.smith@company.com', '2023-01-15'),
    ('Sarah', 'Johnson', 'sarah.johnson@company.com', '2023-03-20'),
    ('Mike', 'Williams', 'mike.williams@company.com', '2023-06-10'),
    ('Emily', 'Brown', 'emily.brown@company.com', '2023-09-05'),
    ('David', 'Jones', 'david.jones@company.com', '2024-01-08');

-- Insert IT department employee accounts (one-to-many relationships)
INSERT INTO it_department.employee_accounts (employee_id, service_name, email, username, password) VALUES
    -- John Smith's accounts
    (1, 'Figma', 'john.smith@company.com', 'john_smith', 'figma123'),
    (1, 'Slack', 'john.smith@company.com', 'john.smith', 'slack456'),
    (1, 'ChatGPT', 'john.smith@company.com', 'john_smith_ai', 'gpt789'),
    (1, 'Jira', 'john.smith@company.com', 'jsmith', 'jira321'),
    
    -- Sarah Johnson's accounts
    (2, 'Figma', 'sarah.johnson@company.com', 'sarah_j', 'figma654'),
    (2, 'Slack', 'sarah.johnson@company.com', 'sarah.johnson', 'slack789'),
    (2, 'GitHub', 'sarah.johnson@company.com', 'sjohnson_dev', 'github123'),
    
    -- Mike Williams' accounts
    (3, 'Slack', 'mike.williams@company.com', 'mike.w', 'slack321'),
    (3, 'ChatGPT', 'mike.williams@company.com', 'mike_ai', 'gpt456'),
    (3, 'AWS', 'mike.williams@company.com', 'mike.williams', 'aws789'),
    
    -- Emily Brown's accounts
    (4, 'Figma', 'emily.brown@company.com', 'emily_b', 'figma987'),
    (4, 'Slack', 'emily.brown@company.com', 'emily.brown', 'slack654'),
    
    -- David Jones' accounts
    (5, 'Slack', 'david.jones@company.com', 'david.j', 'slack147'),
    (5, 'ChatGPT', 'david.jones@company.com', 'david_ai', 'gpt258'),
    (5, 'GitHub', 'david.jones@company.com', 'djones', 'github369'),
    (5, 'Jira', 'david.jones@company.com', 'djones', 'jira147');

-- Insert Finance department employees
INSERT INTO finance_department.employees (first_name, last_name, email, hire_date) VALUES
    ('Jennifer', 'Davis', 'jennifer.davis@company.com', '2022-11-01'),
    ('Robert', 'Miller', 'robert.miller@company.com', '2023-02-14'),
    ('Lisa', 'Garcia', 'lisa.garcia@company.com', '2023-07-22'),
    ('James', 'Rodriguez', 'james.rodriguez@company.com', '2023-10-30');

-- Insert Finance department employee accounts
INSERT INTO finance_department.employee_accounts (employee_id, service_name, email, username, password) VALUES
    -- Jennifer Davis' accounts
    (1, 'Slack', 'jennifer.davis@company.com', 'jennifer.d', 'slack159'),
    (1, 'QuickBooks', 'jennifer.davis@company.com', 'jdavis_fin', 'qb753'),
    (1, 'Excel Online', 'jennifer.davis@company.com', 'jennifer.davis', 'excel456'),
    
    -- Robert Miller's accounts
    (2, 'Slack', 'robert.miller@company.com', 'robert.m', 'slack753'),
    (2, 'QuickBooks', 'robert.miller@company.com', 'rmiller', 'qb159'),
    (2, 'SAP', 'robert.miller@company.com', 'robert.miller', 'sap456'),
    
    -- Lisa Garcia's accounts
    (3, 'Slack', 'lisa.garcia@company.com', 'lisa.g', 'slack852'),
    (3, 'Excel Online', 'lisa.garcia@company.com', 'lgarcia', 'excel753'),
    
    -- James Rodriguez' accounts
    (4, 'Slack', 'james.rodriguez@company.com', 'james.r', 'slack951'),
    (4, 'QuickBooks', 'james.rodriguez@company.com', 'jrodriguez', 'qb852'),
    (4, 'SAP', 'james.rodriguez@company.com', 'james.rodriguez', 'sap159');

-- Create indexes for better query performance
CREATE INDEX idx_it_emp_email ON it_department.employees(email);
CREATE INDEX idx_it_acc_employee ON it_department.employee_accounts(employee_id);
CREATE INDEX idx_it_acc_service ON it_department.employee_accounts(service_name);

CREATE INDEX idx_fin_emp_email ON finance_department.employees(email);
CREATE INDEX idx_fin_acc_employee ON finance_department.employee_accounts(employee_id);
CREATE INDEX idx_fin_acc_service ON finance_department.employee_accounts(service_name);