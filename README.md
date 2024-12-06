
# Log Analysis Script

## Assignment: Log Analysis Script

### Objective
The goal of this assignment is to assess your ability to write a Python script that processes log files to extract and analyze key information. This assignment evaluates your proficiency in file handling, string manipulation, and data analysis, which are essential skills for cybersecurity-related programming tasks.

---

### Core Requirements
Your Python script should implement the following functionalities:

#### 1. Count Requests per IP Address
- Parse the provided log file to extract all IP addresses.
- Calculate the number of requests made by each IP address.
- Sort and display the results in descending order of request counts.

**Example Output:**
```
IP Address           Request Count
192.168.1.1          234
203.0.113.5          187
10.0.0.2             92
```

---

#### 2. Identify the Most Frequently Accessed Endpoint
- Extract the endpoints (e.g., URLs or resource paths) from the log file.
- Identify the endpoint accessed the highest number of times.
- Provide the endpoint name and its access count.

**Example Output:**
```
Most Frequently Accessed Endpoint:
/home (Accessed 403 times)
```

---

#### 3. Detect Suspicious Activity
- Identify potential brute force login attempts by:
  - Searching for log entries with failed login attempts (e.g., HTTP status code 401 or a specific failure message like "Invalid credentials").
  - Flagging IP addresses with failed login attempts exceeding a configurable threshold (default: 10 attempts).
- Display the flagged IP addresses and their failed login counts.

**Example Output:**
```
Suspicious Activity Detected:
IP Address           Failed Login Attempts
192.168.1.100        56
203.0.113.34         12
```

---

### How to Use
1. Clone this repository:
   ```bash
   git clone https://github.com/saurabhbutale/VRV_Security_Python_Intern_Assignment.git
   cd VRV_Security_Python_Intern_Assignment
   ```
2. Place the log file (`sample.log`) in the project directory.
3. Run the script:
   ```bash
   python Script.py
   ```
4. View the results in the console.

---

### Requirements
- **Python Version:** Python 3.8 or higher
- **Dependencies:** No external libraries required (uses standard Python libraries)

---

### Configuration
The threshold for detecting suspicious activities can be configured in the script by modifying the `FAILED_LOGIN_THRESHOLD` variable.

---

### Project Structure
```
VRV_Security_Python_Intern_Assignment/
├── Script.py       # The main Python script
├── sample.log      # Example log file (replace with your own log file)
├── README.md       # Project documentation
└── .gitignore      # Ignore unnecessary files
```

---

### License
This project is for educational purposes only. All rights reserved.
