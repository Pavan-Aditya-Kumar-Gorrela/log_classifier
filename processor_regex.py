import re
def classify_with_regex(log_message):
    regex_pattern = {
       # Cluster 0
        r"nova\.osapi_compute\.wsgi\.server \[req-[a-f0-9-]+\]" : "HTTP Status" ,

        # Cluster -1
        r'(Unauthorized access|Suspicious login activity|Abnormal system behavior|Server [0-9]+ (restarted|crashed) unexpectedly)':"Security Alert",

        # Cluster 4
        r'nova\.compute\.claims \[req-[a-f0-9-]+\]':"Resource Usage",

        # Cluster 10
        r'User User[0-9]+ (logged (in|out))\.':"User Action",

        # Cluster 12
        r"Backup (started|ended) at .*" : "System Notification",

        # Cluster 6
        r'(Multiple (bad login attempts|login failures) detected|User [0-9]+ made multiple incorrect login attempts)':"Security Alert",

        # Cluster 7
        r'Backup completed successfully\.':"System Notification",

        # Cluster 17
        r'System updated to version [0-9]+\.[0-9]+\.[0-9]+\.':"System Notification",

        # Cluster 2
        r'(Shard [0-9]+ replication task (ended in failure|did not complete)|Replication of data to shard [0-9]+ failed)':"Error",

        # Cluster 3
        r'File data_[0-9]+\.csv uploaded successfully by user User[0-9]+\.':"System Notification",

        # Cluster 21
        r'Disk cleanup completed successfully\.':"System Notification",

        # Cluster 5
        r'(Critical system (unit|element|part) (error|malfunction|is down): (unit|element|part) ID Component[0-9]+)':"Critical Error",

        # Cluster 13
        r'System reboot initiated by user User[0-9]+\.':"System Notification",

        # Cluster 14
        r'(Denied access attempt|Account Account[0-9]+ (blocked|access denied|login attempt was not successful))':"Security Alert",

        # Cluster 8
        r'Account with ID [0-9]+ created by User[0-9]+\.':"User Action",

        # Cluster 16
        r'(User [0-9]+ (tried to bypass|failed to provide|made an unauthorized|attempted to access) API (security measures|access credentials|request|without proper credentials))':"Security Alert",

        # Cluster 1
        r'(Email (service|server|system) (encountered|experiencing) (issues|fault|problem)|Service disruption caused by email sending error)':"Error",

        # Cluster 9
        r'nova\.compute\.resource_tracker \[req-[a-f0-9-]+\]':"Resource Usage",

        # Cluster 23
        r'(Service health check (was not successful|failure)|Invalid SSL certificate (resulted in|caused) (a failed|the) service health check)':"Error",

        # Cluster 24
        r'(Module X (experienced|reported|failed|was invalid))':"Error",

        # Cluster 19
        r'(Detection of multiple disk faults|RAID array (suffered|experienced) multiple (hard drive|disk) (failures|crashes))':"Critical Error",

        # Cluster 15
        r'(Boot process terminated|System encountered kernel (panic|failure)|Boot sequence failed due to kernel panic)':"Critical Error",

        # Cluster 18
        r'(System configuration (is no longer valid|is experiencing errors|malfunction)|Configuration is corrupted throughout the system)':"Critical Error",

        # Cluster 28
        r'(Admin privilege escalation alert|Potential security threat: Admin privilege escalation|Warning: Potential admin privilege escalation)':"Security Alert"
    }
    for pattern , label in regex_pattern.items():
        if re.search(pattern , log_message , re.IGNORECASE):
            return label
    return None

if __name__ == "__main__":
    print(classify_with_regex("Backup completed successfully."))
    print(classify_with_regex("Account with ID 1234 created by User1."))
    print(classify_with_regex("Hey Bro, chill ya!"))