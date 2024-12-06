import re
import csv
from collections import defaultdict

# File paths
LOG_FILE = 'Sample_Input.log'
OUTPUT_CSV = 'log_analysis_results.csv'

# Threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """Reads the log file and returns a list of log entries."""
    with open(file_path, 'r') as file:
        return file.readlines()

def count_requests_per_ip(log_entries):
    """Counts requests per IP address."""
    ip_count = defaultdict(int)
    for entry in log_entries:
        match = re.match(r'(\d+\.\d+\.\d+\.\d+)', entry)
        if match:
            ip_count[match.group(1)] += 1
    return sorted(ip_count.items(), key=lambda x: x[1], reverse=True)

def most_frequently_accessed_endpoint(log_entries):
    """Identifies the most frequently accessed endpoint."""
    endpoint_count = defaultdict(int)
    for entry in log_entries:
        match = re.search(r'"(?:GET|POST|PUT|DELETE) ([^ ]+)', entry)
        if match:
            endpoint_count[match.group(1)] += 1
    if endpoint_count:
        endpoint, count = max(endpoint_count.items(), key=lambda x: x[1])
        return endpoint, count
    return None, 0

def detect_suspicious_activity(log_entries, threshold=FAILED_LOGIN_THRESHOLD):
    """Detects suspicious activity based on failed login attempts."""
    failed_logins = defaultdict(int)
    for entry in log_entries:
        if '401' in entry or 'Invalid credentials' in entry:
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)', entry)
            if match:
                failed_logins[match.group(1)] += 1
    return {ip: count for ip, count in failed_logins.items() if count > threshold}

def save_results_to_csv(ip_requests, endpoint, suspicious_ips, file_path):
    """Saves analysis results to a CSV file."""
    with open(file_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Requests per IP
        writer.writerow(['IP Address', 'Request Count'])
        writer.writerows(ip_requests)
        writer.writerow([])

        # Most accessed endpoint
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow(endpoint)
        writer.writerow([])

        # Suspicious activity
        writer.writerow(['Suspicious Activity Detected'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        writer.writerows(suspicious_ips.items())

def display_results(ip_requests, endpoint, suspicious_ips):
    """Displays the results in the terminal."""
    print("Requests per IP:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in ip_requests:
        print(f"{ip:<20} {count:<15}")
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{endpoint[0]} (Accessed {endpoint[1]} times)")
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<15}")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count:<15}")

def main():
    # Parse the log file
    log_entries = parse_log_file(LOG_FILE)
    
    # Count requests per IP
    ip_requests = count_requests_per_ip(log_entries)
    
    # Find the most frequently accessed endpoint
    endpoint, endpoint_count = most_frequently_accessed_endpoint(log_entries)
    
    # Detect suspicious activity
    suspicious_ips = detect_suspicious_activity(log_entries)
    
    # Display results
    display_results(ip_requests, (endpoint, endpoint_count), suspicious_ips)
    
    # Save results to CSV
    save_results_to_csv(ip_requests, (endpoint, endpoint_count), suspicious_ips, OUTPUT_CSV)
    print(f"\nResults saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
