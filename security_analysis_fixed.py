import pandas as pd
import numpy as np
import pyodbc
from datetime import datetime, timedelta
import random
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
import warnings
warnings.filterwarnings('ignore')

class SecurityMonitoringSystem:
    def __init__(self, server_name='LAPTOP-ETV2ILGQ\\SQLEXPRESS', database_name='SecurityMonitoringDB'):
        """
        Initialize the Security Monitoring System
        
        Args:
            server_name (str): SQL Server instance name
            database_name (str): Database name
        """
        self.server_name = server_name
        self.database_name = database_name
        self.connection_string = f"""
            DRIVER={{ODBC Driver 17 for SQL Server}};
            SERVER={server_name};
            DATABASE={database_name};
            Trusted_Connection=yes;
        """
        self.anomaly_detector = None
        self.label_encoders = {}
        
    def connect_to_database(self):
        """Establish database connection"""
        try:
            connection = pyodbc.connect(self.connection_string)
            print("[SUCCESS] Successfully connected to SQL Server database")
            return connection
        except Exception as e:
            print(f"[ERROR] Error connecting to database: {e}")
            return None
    
    def generate_sample_data(self, num_records=1000):
        """
        Generate sample user access log data
        
        Args:
            num_records (int): Number of sample records to generate
        """
        print(f"Generating {num_records} sample access log records...")
        
        # Sample data parameters
        user_ids = ['USR001', 'USR002', 'USR003', 'USR004', 'USR005']
        usernames = ['john.smith', 'sarah.jones', 'mike.wilson', 'lisa.brown', 'david.garcia']
        cities = ['New York', 'Los Angeles', 'Chicago', 'Houston', 'Phoenix', 'Philadelphia', 'San Antonio']
        countries = ['USA', 'Canada', 'UK', 'Germany', 'France']
        device_types = ['Desktop', 'Mobile', 'Tablet', 'Laptop']
        
        # Generate sample data
        sample_data = []
        base_time = datetime.now() - timedelta(days=30)
        
        for i in range(num_records):
            user_id = random.choice(user_ids)
            username = usernames[user_ids.index(user_id)]
            
            # Generate login time (weighted towards business hours)
            login_time = base_time + timedelta(
                days=random.randint(0, 30),
                hours=random.choices(
                    range(24), 
                    weights=[1, 1, 1, 1, 1, 2, 3, 5, 8, 10, 10, 10, 10, 10, 8, 6, 4, 3, 2, 1, 1, 1, 1, 1],
                    k=1
                )[0],
                minutes=random.randint(0, 59)
            )
            
            # Generate IP address
            ip_address = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
            
            # Generate login status (95% success, 5% failed)
            login_status = random.choices(['Success', 'Failed'], weights=[95, 5], k=1)[0]
            
            # Generate other fields
            city = random.choice(cities)
            country = random.choice(countries)
            device_type = random.choice(device_types)
            
            # Calculate session duration (only for successful logins)
            session_duration = random.randint(15, 480) if login_status == 'Success' else None
            
            # Calculate risk score based on various factors
            risk_score = self.calculate_risk_score(login_time, city, country, login_status)
            
            sample_data.append({
                'UserID': user_id,
                'Username': username,
                'LoginTime': login_time,
                'IPAddress': ip_address,
                'LocationCity': city,
                'LocationCountry': country,
                'DeviceType': device_type,
                'LoginStatus': login_status,
                'SessionDuration': session_duration,
                'RiskScore': risk_score
            })
        
        return pd.DataFrame(sample_data)
    
    def calculate_risk_score(self, login_time, city, country, login_status):
        """Calculate risk score based on various factors"""
        risk_score = 0.0
        
        # Time-based risk (higher risk for off-hours)
        hour = login_time.hour
        if hour < 6 or hour > 22:
            risk_score += 30
        elif hour < 8 or hour > 18:
            risk_score += 15
        
        # Location-based risk (higher risk for certain locations)
        if country != 'USA':
            risk_score += 25
        
        # Status-based risk
        if login_status == 'Failed':
            risk_score += 40
        
        # Add some randomness
        risk_score += random.uniform(-5, 15)
        
        return max(0, min(100, risk_score))
    
    def insert_sample_data(self, df):
        """Insert sample data into the database"""
        connection = self.connect_to_database()
        if not connection:
            return False
        
        try:
            cursor = connection.cursor()
            
            # Insert data
            for _, row in df.iterrows():
                insert_query = """
                INSERT INTO UserAccessLogs 
                (UserID, Username, LoginTime, IPAddress, LocationCity, LocationCountry, 
                 DeviceType, LoginStatus, SessionDuration, RiskScore)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                cursor.execute(insert_query, (
                    row['UserID'], row['Username'], row['LoginTime'], row['IPAddress'],
                    row['LocationCity'], row['LocationCountry'], row['DeviceType'],
                    row['LoginStatus'], row['SessionDuration'], row['RiskScore']
                ))
            
            connection.commit()
            print(f"[SUCCESS] Successfully inserted {len(df)} records into database")
            return True
            
        except Exception as e:
            print(f"[ERROR] Error inserting data: {e}")
            return False
        finally:
            connection.close()
    
    def fetch_access_logs(self, days_back=30):
        """Fetch access logs from database"""
        connection = self.connect_to_database()
        if not connection:
            return None
        
        try:
            query = f"""
            SELECT ual.*, u.Department, u.Role, u.Email
            FROM UserAccessLogs ual
            JOIN Users u ON ual.UserID = u.UserID
            WHERE ual.LoginTime >= DATEADD(day, -{days_back}, GETDATE())
            ORDER BY ual.LoginTime DESC
            """
            
            df = pd.read_sql_query(query, connection)
            print(f"[SUCCESS] Fetched {len(df)} access log records")
            return df
            
        except Exception as e:
            print(f"[ERROR] Error fetching data: {e}")
            return None
        finally:
            connection.close()
    
    def prepare_features_for_ml(self, df):
        """Prepare features for machine learning anomaly detection"""
        if df is None or df.empty:
            return None
        
        # Create a copy for processing
        ml_df = df.copy()
        
        # Convert datetime to numerical features
        ml_df['LoginTime'] = pd.to_datetime(ml_df['LoginTime'])
        ml_df['hour'] = ml_df['LoginTime'].dt.hour
        ml_df['day_of_week'] = ml_df['LoginTime'].dt.dayofweek
        ml_df['is_weekend'] = ml_df['day_of_week'].isin([5, 6]).astype(int)
        
        # Encode categorical variables
        categorical_columns = ['UserID', 'LocationCity', 'LocationCountry', 'DeviceType', 'Department', 'Role']
        
        for col in categorical_columns:
            if col in ml_df.columns:
                if col not in self.label_encoders:
                    self.label_encoders[col] = LabelEncoder()
                    ml_df[f'{col}_encoded'] = self.label_encoders[col].fit_transform(ml_df[col].astype(str))
                else:
                    ml_df[f'{col}_encoded'] = self.label_encoders[col].transform(ml_df[col].astype(str))
        
        # Create login success indicator
        ml_df['login_failed'] = (ml_df['LoginStatus'] == 'Failed').astype(int)
        
        # Select features for anomaly detection
        feature_columns = [
            'hour', 'day_of_week', 'is_weekend', 'login_failed', 'RiskScore',
            'UserID_encoded', 'LocationCity_encoded', 'LocationCountry_encoded', 
            'DeviceType_encoded', 'Department_encoded', 'Role_encoded'
        ]
        
        # Filter only existing columns
        available_features = [col for col in feature_columns if col in ml_df.columns]
        
        return ml_df[available_features]
    
    def detect_anomalies(self, df):
        """Detect anomalies using Isolation Forest"""
        features_df = self.prepare_features_for_ml(df)
        
        if features_df is None or features_df.empty:
            print("[ERROR] No features available for anomaly detection")
            return df
        
        # Train Isolation Forest
        self.anomaly_detector = IsolationForest(
            contamination=0.1,  # Expect 10% anomalies
            random_state=42,
            n_estimators=100
        )
        
        # Fit and predict
        anomaly_scores = self.anomaly_detector.fit_predict(features_df)
        anomaly_scores_normalized = self.anomaly_detector.score_samples(features_df)
        
        # Add results to original dataframe
        result_df = df.copy()
        result_df['is_anomaly'] = (anomaly_scores == -1).astype(int)
        result_df['anomaly_score'] = anomaly_scores_normalized
        
        num_anomalies = sum(anomaly_scores == -1)
        print(f"[SUCCESS] Detected {num_anomalies} anomalies out of {len(df)} records")
        
        return result_df
    
    def generate_security_alerts(self, df):
        """Generate security alerts based on detected patterns"""
        alerts = []
        
        if df is None or df.empty:
            return alerts
        
        # Convert LoginTime to datetime if it's not already
        df['LoginTime'] = pd.to_datetime(df['LoginTime'])
        
        # Alert 1: Multiple failed logins
        failed_logins = df[df['LoginStatus'] == 'Failed'].groupby('UserID').size()
        for user_id, count in failed_logins.items():
            if count >= 3:  # More than 3 failed attempts
                alerts.append({
                    'UserID': user_id,
                    'AlertType': 'Multiple Failed Logins',
                    'Description': f'User has {count} failed login attempts',
                    'Severity': 'High' if count >= 5 else 'Medium',
                    'AlertTime': datetime.now()
                })
        
        # Alert 2: Off-hours access
        off_hours = df[(df['LoginTime'].dt.hour < 6) | (df['LoginTime'].dt.hour > 22)]
        for _, row in off_hours.iterrows():
            alerts.append({
                'UserID': row['UserID'],
                'AlertType': 'Off Hours Access',
                'Description': f'Login at {row["LoginTime"].strftime("%H:%M")} outside business hours',
                'Severity': 'Medium',
                'AlertTime': datetime.now()
            })
        
        # Alert 3: High risk score logins
        high_risk = df[df['RiskScore'] > 70]
        for _, row in high_risk.iterrows():
            alerts.append({
                'UserID': row['UserID'],
                'AlertType': 'High Risk Login',
                'Description': f'Login with risk score {row["RiskScore"]:.1f}',
                'Severity': 'High' if row['RiskScore'] > 85 else 'Medium',
                'AlertTime': datetime.now()
            })
        
        # Alert 4: Anomalies detected by ML
        if 'is_anomaly' in df.columns:
            anomalies = df[df['is_anomaly'] == 1]
            for _, row in anomalies.iterrows():
                alerts.append({
                    'UserID': row['UserID'],
                    'AlertType': 'Anomalous Behavior',
                    'Description': f'ML detected unusual login pattern (score: {row["anomaly_score"]:.2f})',
                    'Severity': 'Medium',
                    'AlertTime': datetime.now()
                })
        
        print(f"[SUCCESS] Generated {len(alerts)} security alerts")
        return alerts
    
    def export_data_for_powerbi(self, df, alerts, output_dir="powerbi_data"):
        """Export processed data for Power BI consumption"""
        import os
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Export main access logs
        if df is not None and not df.empty:
            df.to_csv(f"{output_dir}/access_logs_processed.csv", index=False)
            print(f"[SUCCESS] Exported access logs to {output_dir}/access_logs_processed.csv")
        
        # Export alerts
        if alerts:
            alerts_df = pd.DataFrame(alerts)
            alerts_df.to_csv(f"{output_dir}/security_alerts.csv", index=False)
            print(f"[SUCCESS] Exported alerts to {output_dir}/security_alerts.csv")
        
        # Export summary statistics
        if df is not None and not df.empty:
            summary_stats = {
                'total_logins': len(df),
                'successful_logins': len(df[df['LoginStatus'] == 'Success']),
                'failed_logins': len(df[df['LoginStatus'] == 'Failed']),
                'unique_users': df['UserID'].nunique(),
                'avg_risk_score': df['RiskScore'].mean(),
                'high_risk_logins': len(df[df['RiskScore'] > 70]),
                'anomalies_detected': len(df[df.get('is_anomaly', pd.Series()) == 1])
            }
            
            pd.DataFrame([summary_stats]).to_csv(f"{output_dir}/summary_statistics.csv", index=False)
            print(f"[SUCCESS] Exported summary statistics to {output_dir}/summary_statistics.csv")

# Example usage and testing
def main():
    """Main function to demonstrate the security monitoring system"""
    print("Security Monitoring System - Data Analysis Module")
    print("=" * 60)
    
    # Initialize the system
    sms = SecurityMonitoringSystem()
    
    # Step 1: Generate sample data
    print("\nStep 1: Generating sample data...")
    sample_df = sms.generate_sample_data(1000)
    print(f"Sample data shape: {sample_df.shape}")
    
    # Step 2: Insert sample data (uncomment when database is ready)
    print("\nStep 2: Inserting data into database...")
    success = sms.insert_sample_data(sample_df)
    
    # Step 3: Fetch data from database
    print("\nStep 3: Fetching data from database...")
    if success:
        df = sms.fetch_access_logs(30)
    else:
        print("[WARNING] Using generated sample data instead")
        df = sample_df
    
    if df is None or df.empty:
        print("[WARNING] Using generated sample data instead")
        df = sample_df
    
    # Step 4: Perform anomaly detection
    print("\nStep 4: Performing anomaly detection...")
    analyzed_df = sms.detect_anomalies(df)
    
    # Step 5: Generate security alerts
    print("\nStep 5: Generating security alerts...")
    alerts = sms.generate_security_alerts(analyzed_df)
    
    # Step 6: Export data for Power BI
    print("\nStep 6: Exporting data for Power BI...")
    sms.export_data_for_powerbi(analyzed_df, alerts)
    
    # Step 7: Display summary
    print("\n" + "=" * 60)
    print("ANALYSIS SUMMARY:")
    print("=" * 60)
    print(f"Total records processed: {len(analyzed_df)}")
    print(f"Anomalies detected: {sum(analyzed_df.get('is_anomaly', pd.Series()) == 1)}")
    print(f"Security alerts generated: {len(alerts)}")
    print(f"Average risk score: {analyzed_df['RiskScore'].mean():.2f}")
    
    # Display top alerts
    if alerts:
        print(f"\nTop Security Alerts:")
        print("-" * 40)
        for i, alert in enumerate(alerts[:5]):
            print(f"{i+1}. {alert['AlertType']} - {alert['Severity']}")
            print(f"   User: {alert['UserID']}")
            print(f"   Description: {alert['Description']}")
            print()
    
    print("Analysis completed successfully!")
    print("CSV files exported to 'powerbi_data' folder for Power BI import.")
    
    return analyzed_df, alerts

if __name__ == "__main__":
    try:
        df, alerts = main()
        print("\n[SUCCESS] Security analysis completed successfully!")
        input("\nPress Enter to exit...")
    except Exception as e:
        print(f"\n[ERROR] An error occurred: {e}")
        print("\nTroubleshooting tips:")
        print("1. Ensure SQL Server Express is running")
        print("2. Verify database was created using database_setup_fixed.sql")
        print("3. Check if ODBC Driver 17 for SQL Server is installed")
        print("4. Run this script as Administrator")
        input("\nPress Enter to exit...")