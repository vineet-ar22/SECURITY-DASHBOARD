# This script should be used in Power BI's "Get Data" > "Other" > "Python Script"
# Copy and paste this code into Power BI's Python script dialog

import pandas as pd
import pyodbc
import numpy as np
from datetime import datetime, timedelta

# Database connection configuration
SERVER = 'LAPTOP-ETV2ILGQ\\SQLEXPRESS'  # Change to your SQL Server instance
DATABASE = 'SecurityMonitoringDB'
CONNECTION_STRING = f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={SERVER};DATABASE={DATABASE};Trusted_Connection=yes;'

try:
    # Connect to database
    connection = pyodbc.connect(CONNECTION_STRING)
    
    # Query 1: Access Logs with User Information
    access_logs_query = """
    SELECT 
        ual.LogID,
        ual.UserID,
        ual.Username,
        ual.LoginTime,
        ual.LogoutTime,
        ual.IPAddress,
        ual.LocationCity,
        ual.LocationCountry,
        ual.DeviceType,
        ual.LoginStatus,
        ual.SessionDuration,
        ual.RiskScore,
        u.Department,
        u.Role,
        u.Email,
        CASE 
            WHEN DATEPART(hour, ual.LoginTime) BETWEEN 6 AND 22 THEN 'Business Hours'
            ELSE 'Off Hours'
        END AS TimeCategory,
        CASE 
            WHEN DATEPART(weekday, ual.LoginTime) IN (1, 7) THEN 'Weekend'
            ELSE 'Weekday'
        END AS DayCategory
    FROM UserAccessLogs ual
    JOIN Users u ON ual.UserID = u.UserID
    WHERE ual.LoginTime >= DATEADD(day, -90, GETDATE())
    """
    
    access_logs = pd.read_sql_query(access_logs_query, connection)
    
    # Query 2: Security Alerts
    security_alerts_query = """
    SELECT 
        sa.AlertID,
        sa.UserID,
        sa.AlertType,
        sa.AlertDescription,
        sa.Severity,
        sa.AlertTime,
        sa.IsResolved,
        u.Username,
        u.Department,
        u.Role
    FROM SecurityAlerts sa
    JOIN Users u ON sa.UserID = u.UserID
    WHERE sa.AlertTime >= DATEADD(day, -90, GETDATE())
    """
    
    security_alerts = pd.read_sql_query(security_alerts_query, connection)
    
    # Query 3: Daily Login Summary
    daily_summary_query = """
    SELECT 
        CAST(ual.LoginTime AS DATE) AS LoginDate,
        u.Department,
        u.Role,
        COUNT(*) AS TotalLogins,
        SUM(CASE WHEN ual.LoginStatus = 'Success' THEN 1 ELSE 0 END) AS SuccessfulLogins,
        SUM(CASE WHEN ual.LoginStatus = 'Failed' THEN 1 ELSE 0 END) AS FailedLogins,
        AVG(CAST(ual.RiskScore AS FLOAT)) AS AvgRiskScore,
        COUNT(DISTINCT ual.UserID) AS UniqueUsers
    FROM UserAccessLogs ual
    JOIN Users u ON ual.UserID = u.UserID
    WHERE ual.LoginTime >= DATEADD(day, -90, GETDATE())
    GROUP BY CAST(ual.LoginTime AS DATE), u.Department, u.Role
    """
    
    daily_summary = pd.read_sql_query(daily_summary_query, connection)
    
    # Query 4: User Risk Profile
    user_risk_profile_query = """
    SELECT 
        u.UserID,
        u.Username,
        u.Department,
        u.Role,
        COUNT(*) AS TotalLogins,
        AVG(CAST(ual.RiskScore AS FLOAT)) AS AvgRiskScore,
        MAX(ual.RiskScore) AS MaxRiskScore,
        SUM(CASE WHEN ual.LoginStatus = 'Failed' THEN 1 ELSE 0 END) AS FailedAttempts,
        COUNT(DISTINCT ual.LocationCity) AS UniqueLocations,
        MAX(ual.LoginTime) AS LastLogin
    FROM Users u
    LEFT JOIN UserAccessLogs ual ON u.UserID = ual.UserID
    WHERE u.IsActive = 1
    GROUP BY u.UserID, u.Username, u.Department, u.Role
    """
    
    user_risk_profile = pd.read_sql_query(user_risk_profile_query, connection)
    
    connection.close()
    
    # These DataFrames will be available in Power BI:
    # - access_logs: Detailed access log data
    # - security_alerts: Security alerts and incidents  
    # - daily_summary: Daily aggregated metrics
    # - user_risk_profile: User-level risk assessment
    
except Exception as e:
    print(f"Error: {str(e)}")
    # Create empty DataFrames as fallback
    access_logs = pd.DataFrame()
    security_alerts = pd.DataFrame()  
    daily_summary = pd.DataFrame()
    user_risk_profile = pd.DataFrame()