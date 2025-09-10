-- Step 1: Create Database
CREATE DATABASE SecurityMonitoringDB;
GO

USE SecurityMonitoringDB;
GO

-- Step 2: Create User Access Logs Table
CREATE TABLE UserAccessLogs (
    LogID int IDENTITY(1,1) PRIMARY KEY,
    UserID nvarchar(100) NOT NULL,
    Username nvarchar(100) NOT NULL,
    LoginTime datetime2 NOT NULL DEFAULT GETDATE(),
    LogoutTime datetime2 NULL,
    IPAddress nvarchar(45) NOT NULL,
    UserAgent nvarchar(500) NULL,
    LocationCity nvarchar(100) NULL,
    LocationCountry nvarchar(100) NULL,
    DeviceType nvarchar(50) NULL,
    LoginStatus nvarchar(20) NOT NULL CHECK (LoginStatus IN ('Success', 'Failed', 'Locked')),
    FailureReason nvarchar(200) NULL,
    SessionDuration int NULL, -- in minutes
    AccessedResources nvarchar(MAX) NULL,
    RiskScore decimal(5,2) DEFAULT 0.00,
    CreatedDate datetime2 DEFAULT GETDATE()
);
GO

-- Step 3: Create Users Table for RBAC
CREATE TABLE Users (
    UserID nvarchar(100) PRIMARY KEY,
    Username nvarchar(100) UNIQUE NOT NULL,
    Email nvarchar(255) NOT NULL,
    Department nvarchar(100) NULL,
    Role nvarchar(100) NOT NULL,
    Manager nvarchar(100) NULL,
    IsActive bit DEFAULT 1,
    CreatedDate datetime2 DEFAULT GETDATE(),
    LastModified datetime2 DEFAULT GETDATE()
);
GO

-- Step 4: Create Roles Table
CREATE TABLE Roles (
    RoleID int IDENTITY(1,1) PRIMARY KEY,
    RoleName nvarchar(100) UNIQUE NOT NULL,
    Description nvarchar(500) NULL,
    PermissionLevel int NOT NULL DEFAULT 1, -- 1=Basic, 2=Intermediate, 3=Advanced, 4=Admin
    CreatedDate datetime2 DEFAULT GETDATE()
);
GO

-- Step 5: Create Security Alerts Table
CREATE TABLE SecurityAlerts (
    AlertID int IDENTITY(1,1) PRIMARY KEY,
    UserID nvarchar(100) NOT NULL,
    AlertType nvarchar(100) NOT NULL, -- 'Multiple Failed Logins', 'Unusual Location', 'Off Hours Access', etc.
    AlertDescription nvarchar(MAX) NOT NULL,
    Severity nvarchar(20) NOT NULL CHECK (Severity IN ('Low', 'Medium', 'High', 'Critical')),
    AlertTime datetime2 DEFAULT GETDATE(),
    IsResolved bit DEFAULT 0,
    ResolvedBy nvarchar(100) NULL,
    ResolvedDate datetime2 NULL,
    Notes nvarchar(MAX) NULL,
    FOREIGN KEY (UserID) REFERENCES Users(UserID)
);
GO

-- Step 6: Create Audit Trail Table
CREATE TABLE AuditTrail (
    AuditID int IDENTITY(1,1) PRIMARY KEY,
    UserID nvarchar(100) NOT NULL,
    Action nvarchar(200) NOT NULL,
    TableName nvarchar(100) NULL,
    RecordID nvarchar(100) NULL,
    OldValues nvarchar(MAX) NULL,
    NewValues nvarchar(MAX) NULL,
    ActionTime datetime2 DEFAULT GETDATE(),
    IPAddress nvarchar(45) NULL,
    FOREIGN KEY (UserID) REFERENCES Users(UserID)
);
GO

-- Step 7: Insert Sample Roles
INSERT INTO Roles (RoleName, Description, PermissionLevel) VALUES
('Admin', 'Full system access and user management', 4),
('Security Analyst', 'Access to security logs and alerts', 3),
('Manager', 'Department-level access and reporting', 2),
('Employee', 'Basic access to personal data only', 1),
('Auditor', 'Read-only access to audit logs and compliance data', 3);
GO

-- Step 8: Insert Sample Users
INSERT INTO Users (UserID, Username, Email, Department, Role) VALUES
('USR001', 'john.smith', 'john.smith@company.com', 'IT', 'Admin'),
('USR002', 'sarah.jones', 'sarah.jones@company.com', 'Security', 'Security Analyst'),
('USR003', 'mike.wilson', 'mike.wilson@company.com', 'Finance', 'Manager'),
('USR004', 'lisa.brown', 'lisa.brown@company.com', 'HR', 'Employee'),
('USR005', 'david.garcia', 'david.garcia@company.com', 'Compliance', 'Auditor');
GO

-- Step 9: Create Views for Security Dashboard
CREATE VIEW vw_LoginSummary AS
SELECT 
    u.Department,
    u.Role,
    COUNT(*) as TotalLogins,
    SUM(CASE WHEN ual.LoginStatus = 'Success' THEN 1 ELSE 0 END) as SuccessfulLogins,
    SUM(CASE WHEN ual.LoginStatus = 'Failed' THEN 1 ELSE 0 END) as FailedLogins,
    AVG(ual.RiskScore) as AvgRiskScore,
    MAX(ual.LoginTime) as LastLogin
FROM UserAccessLogs ual
JOIN Users u ON ual.UserID = u.UserID
WHERE ual.LoginTime >= DATEADD(day, -30, GETDATE())
GROUP BY u.Department, u.Role;
GO

-- Step 10: Create Stored Procedure for Anomaly Detection
CREATE PROCEDURE sp_DetectAnomalies
AS
BEGIN
    -- Detect multiple failed login attempts (>5 in 1 hour)
    INSERT INTO SecurityAlerts (UserID, AlertType, AlertDescription, Severity)
    SELECT 
        UserID,
        'Multiple Failed Logins',
        'User has ' + CAST(COUNT(*) AS nvarchar(10)) + ' failed login attempts in the last hour',
        'High'
    FROM UserAccessLogs
    WHERE LoginStatus = 'Failed'
        AND LoginTime >= DATEADD(hour, -1, GETDATE())
    GROUP BY UserID
    HAVING COUNT(*) > 5
        AND UserID NOT IN (
            SELECT UserID FROM SecurityAlerts 
            WHERE AlertType = 'Multiple Failed Logins' 
                AND AlertTime >= DATEADD(hour, -1, GETDATE())
        );

    -- Detect unusual location logins
    INSERT INTO SecurityAlerts (UserID, AlertType, AlertDescription, Severity)
    SELECT DISTINCT
        ual.UserID,
        'Unusual Location',
        'Login from new location: ' + ual.LocationCity + ', ' + ual.LocationCountry,
        'Medium'
    FROM UserAccessLogs ual
    WHERE ual.LoginTime >= DATEADD(day, -1, GETDATE())
        AND ual.LoginStatus = 'Success'
        AND NOT EXISTS (
            SELECT 1 FROM UserAccessLogs ual2
            WHERE ual2.UserID = ual.UserID
                AND ual2.LocationCity = ual.LocationCity
                AND ual2.LoginTime < DATEADD(day, -30, GETDATE())
        );
END;
GO

-- Step 11: Create additional useful views
CREATE VIEW vw_SecurityAlertsSummary AS
SELECT 
    AlertType,
    Severity,
    COUNT(*) as AlertCount,
    COUNT(CASE WHEN IsResolved = 1 THEN 1 END) as ResolvedCount,
    COUNT(CASE WHEN IsResolved = 0 THEN 1 END) as OpenCount,
    MAX(AlertTime) as LastAlertTime
FROM SecurityAlerts
WHERE AlertTime >= DATEADD(day, -30, GETDATE())
GROUP BY AlertType, Severity;
GO

CREATE VIEW vw_UserRiskProfile AS
SELECT 
    u.UserID,
    u.Username,
    u.Email,
    u.Department,
    u.Role,
    COUNT(ual.LogID) as TotalLogins,
    AVG(CAST(ual.RiskScore AS FLOAT)) as AvgRiskScore,
    MAX(ual.RiskScore) as MaxRiskScore,
    SUM(CASE WHEN ual.LoginStatus = 'Failed' THEN 1 ELSE 0 END) as FailedAttempts,
    COUNT(DISTINCT ual.LocationCity) as UniqueLocations,
    MAX(ual.LoginTime) as LastLogin
FROM Users u
LEFT JOIN UserAccessLogs ual ON u.UserID = ual.UserID
WHERE u.IsActive = 1
GROUP BY u.UserID, u.Username, u.Email, u.Department, u.Role;
GO

-- Step 12: Create indexes for better performance
CREATE INDEX IX_UserAccessLogs_UserID ON UserAccessLogs(UserID);
CREATE INDEX IX_UserAccessLogs_LoginTime ON UserAccessLogs(LoginTime);
CREATE INDEX IX_UserAccessLogs_LoginStatus ON UserAccessLogs(LoginStatus);
CREATE INDEX IX_UserAccessLogs_RiskScore ON UserAccessLogs(RiskScore);
CREATE INDEX IX_SecurityAlerts_UserID ON SecurityAlerts(UserID);
CREATE INDEX IX_SecurityAlerts_AlertTime ON SecurityAlerts(AlertTime);
CREATE INDEX IX_SecurityAlerts_Severity ON SecurityAlerts(Severity);
GO

-- Step 13: Grant permissions (optional - uncomment if needed)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON UserAccessLogs TO [SecurityAnalystRole];
-- GRANT SELECT ON vw_LoginSummary TO [SecurityAnalystRole];
-- GRANT SELECT ON vw_SecurityAlertsSummary TO [SecurityAnalystRole];
-- GRANT SELECT ON vw_UserRiskProfile TO [SecurityAnalystRole];
-- GO

-- Step 14: Final verification
SELECT 'Database setup completed successfully!' as Status;
SELECT 'Tables created: ' + CAST(COUNT(*) AS nvarchar(10)) as TablesCount
FROM INFORMATION_SCHEMA.TABLES 
WHERE TABLE_TYPE = 'BASE TABLE' AND TABLE_SCHEMA = 'dbo';

SELECT 'Views created: ' + CAST(COUNT(*) AS nvarchar(10)) as ViewsCount
FROM INFORMATION_SCHEMA.VIEWS 
WHERE TABLE_SCHEMA = 'dbo';

SELECT 'Sample users inserted: ' + CAST(COUNT(*) AS nvarchar(10)) as UsersCount
FROM Users;

SELECT 'Sample roles inserted: ' + CAST(COUNT(*) AS nvarchar(10)) as RolesCount
FROM Roles;
GO
