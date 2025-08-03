#main.py
from cryptography.fernet import Fernet
import os
import sys
import questionary
from questionary import Style
import pydoc
import platform
# Ensure these modules are in the same directory or on your Python path

from session import Session 
from key_utils import encrypt_key, decrypt_key 


# ANSI color codes
class Color:
    RESET = "\033[0m"
    GREEN = "\033[92m"
    BOLD = "\033[1m"

# Choices custom style
custom_style = Style([
    ("qmark", "fg:#00BCD4 bold"),
    ("question", "bold"),
    ("answer", "fg:#4CAF50 bold"),
    ("pointer", "fg:#FF5722 bold"),
    ("highlighted", "fg:#FF5722 bold"),
    ("selected", "fg:#00BCD4"),
    ("separator", "fg:#cc5454"),
    ("instruction", "fg:#607D8B"),
    ("text", "fg:#ffffff"),
])

# Create a global session manager instance
session_manager = Session()

def print_banner():
    """Prints the application banner."""
    header_banner = f"""
{Color.GREEN}
========================================================
8888888b.     d8888  .d8888b.   .d8888b.    .d88 888       888 88b.    .d88888b.  8888888b.  8888888b.   .d8888b.  
888   Y88b   d88888 d88P  Y88b d88P  Y88b  d88P" 888   o   888 "Y88b  d88P" "Y88b 888   Y88b 888  "Y88b d88P  Y88b 
888    888  d88P888 Y88b.      Y88b.      d88P   888  d8b  888   Y88b 888     888 888    888 888    888 Y88b.      
888   d88P d88P 888  "Y888b.    "Y888b.   888    888 d888b 888    888 888     888 888   d88P 888    888  "Y888b.   
8888888P" d88P  888     "Y88b.     "Y88b. 888    888d88888b888    888 888     888 8888888P"  888    888     "Y88b. 
888      d88P   888       "888       "888 Y88b   88888P Y88888   d88P 888     888 888 T88b   888    888       "888 
888     d8888888888 Y88b  d88P Y88b  d88P  Y88b. 8888P   Y8888 .d88P  Y88b. .d88P 888  T88b  888  .d88P Y88b  d88P 
888    d88P     888  "Y8888P"   "Y8888P"    "Y88 888P     Y888 88P"    "Y88888P"  888   T88b 8888888P"   "Y8888P"  
                                                        ============================================================
by WINK
{Color.RESET}
"""
    print(header_banner)


def safe_ask(question_fn, *args, on_cancel=None, **kwargs):
    """
    Wraps questionary.ask() to handle None return (user cancelled)
    or KeyboardInterrupt.
    """
    try:
        answer = question_fn(*args, **kwargs).ask()
        if answer is None:
            if on_cancel:
                on_cancel()
            else:
                sys.exit(0)
        return answer
    except KeyboardInterrupt:
        if on_cancel:
            on_cancel()
        else:
            sys.exit(0)


def display_message(type_, service=None, message=None):
    """
    Displays a formatted message to the user with emojis and colors.
    Supports different message types like success, error, info, etc.
    """
    emojis = {
        "success": "✅",
        "error": "❌",
        "warning": "⚠️",
        "info": "ℹ️",
        "add": "📝",
        "wait": "🔙"
    }

    styles = {
        "success": "fg:green bold",
        "error": "fg:red bold",
        "warning": "fg:yellow bold",
        "info": "fg:blue bold",
        "add": "fg:cyan bold",
        "wait": "fg:magenta italic"
    }

    default_messages = {
        "success": f"Password for '{service}' saved successfully!" if service else "Success!",
        "error": "An error occurred.",
        "warning": "Something might be wrong.",
        "info": "Here is some information.",
        "add": "Adding a new password...",
        "wait": "Press [Enter] to return..."
    }

    final_message = message or default_messages.get(type_, "")
    emoji = emojis.get(type_, "")
    style = styles.get(type_, "fg:white")
    questionary.print(f"\n{emoji} {final_message}", style=style)
    if type_ == "wait":
        # Wait for user to press Enter
        answer = questionary.text("", style=custom_style).ask()
        if answer is None: # Handle Ctrl+C during wait prompt
            return


def handle_cancel():
    """Handles user cancellation (Ctrl+C) by clearing the screen and exiting."""
    clear()
    print(f"{Color.GREEN}\n[!] Ctrl+C detected. Exiting immediately...{Color.RESET}\n")
    sys.exit(0)


def get_password_inputs(option=None, message=None):
    """
    Prompts the user for password-related inputs based on the option.
    Handles user cancellation for each input.
    """
    if option == "Adding_new_pass":
        service = safe_ask(questionary.text, " 🔧 Enter the service name:", style=custom_style)
        if service is None: return None
        username = safe_ask(questionary.text, " 👤 Enter the username:", style=custom_style)
        if username is None: return None
        password = safe_ask(questionary.text, " 🔑 Enter the password:", style=custom_style)
        if password is None: return None
        return service, username, password
    elif option == "Master_pasword":
        master_pass = safe_ask(questionary.text, f"{message}", style=custom_style, is_password=True)
        if master_pass is None: return None
        return master_pass


def confirm_master_password():
    """
    Authenticates the user with the master password by attempting to decrypt the Fernet key.
    If already authenticated, returns the stored password.
    """
    if session_manager.is_authenticated():
        return session_manager.get_password()

    password = get_password_inputs("Master_pasword", "🔐 Enter master password: ")
    if password is None:
        return None

    try:
        decrypted_fernet_key = decrypt_key(password)
        session_manager.login(password, decrypted_fernet_key)
        display_message("success", message="✅ Successfully authenticated!")
        return password
    except FileNotFoundError:
        display_message("error", message="Encrypted key file not found. Please create a key first.")
        display_message("wait")
        return None
    except Exception: 
        display_message("error", message="Invalid master password or corrupted key file.")
        display_message("wait")
        return None


def create_secure_key_file():
    """
    Creates the master encryption key file ('key.key.enc') and sets up the master password
    if they don't exist. This function should only run once at initial setup.
    """
    if not os.path.exists("key.key.enc"):
        display_message("info", message="First-time setup: Setting up your master password and encryption key.")
        password = get_password_inputs("Master_pasword", "📌 Set a master password: ")
        if password is None: return False
        confirm = get_password_inputs("Master_pasword", "🔁 Confirm password: ")
        if confirm is None: return False

        if password != confirm:
            display_message("error", message="Passwords do not match.")
            display_message("wait")
            return False

        fernet_key = Fernet.generate_key()
        # Use the updated encrypt_key which handles PBKDF2 and salt
        encrypt_key(fernet_key, password)

        display_message("success", message="✅ Master key created and saved securely.")
        display_message("wait")
        return True
    return True # Key file already exists


def load_key():
    """
    Loads the encryption key from the session.
    If not authenticated, prompts for master password.
    """
    if not session_manager.is_authenticated():
        if confirm_master_password() is None:
            return None # Unsuccessful authentication or cancelled

    key = session_manager.get_fernet_key()
    if key:
        return key
    else:
        display_message("error", message="Could not load key from session. Please re-authenticate.")
        display_message("wait")
        return None


def save_password():
    """Encrypts and saves a new password entry."""
    display_message("add")
    result = get_password_inputs("Adding_new_pass")
    if result is None:
        display_message("info", message="Password addition cancelled.")
        display_message("wait")
        return

    key = load_key()
    if key is None:
        return # Authentication failed or cancelled

    service, username, password = result
    cipher = Fernet(key)
    data = f"{service},{username},{password}".encode()
    encrypted_data = cipher.encrypt(data)

    with open("passwords.enc", "ab") as file:
        file.write(encrypted_data + b"\n")

    display_message("success", service=service)
    display_message("wait")


def view_passwords():
    """Decrypts and displays all stored passwords."""
    key = load_key()
    if key is None:
        return
    cipher = Fernet(key)

    if not os.path.exists("passwords.enc") or os.stat("passwords.enc").st_size == 0:
        display_message("info", message="No passwords stored yet.")
        display_message("wait")
        return

    output = []
    bold_start = f"{Color.BOLD}" if platform.system().lower() != "windows" else ""
    bold_end = f"{Color.RESET}" if platform.system().lower() != "windows" else ""

    with open("passwords.enc", "rb") as file:
        for index, line in enumerate(file, start=1):
            encrypted_data = line.strip()
            if not encrypted_data: # Skip empty lines
                continue
            try:
                decrypted_data = cipher.decrypt(encrypted_data).decode()
                service, username, password = decrypted_data.split(",", 2)
                line_output = f"{bold_start}{index}. 🔐 Service: {service}, Username: {username}, Password: {password}{bold_end}"
            except Exception as e:
                line_output = f"{index}. ❌ Error decrypting entry: {e} (Corrupted or invalid entry)"
            output.append(line_output)

    if not output:
        display_message("info", message="No valid passwords found after decryption.")
        display_message("wait")
        return

    if platform.system().lower() == "windows":
        for line in output:
            questionary.print(line, style="fg:white")
    else:
        try:
            pydoc.pager("\n".join(output))
        except Exception as e:
            display_message("error", message=f"❌ Pager error: {e}. Displaying directly.")
            for line in output:
                questionary.print(line, style="fg:white")

    display_message("wait")


def search_password():
    """Searches for a specific password by service name."""
    service_name = safe_ask(questionary.text, "Enter the service name to search:", style=custom_style)
    if service_name is None:
        display_message("info", message="Search cancelled.")
        display_message("wait")
        return

    key = load_key()
    if key is None:
        return
    cipher = Fernet(key)

    if not os.path.exists("passwords.enc") or os.stat("passwords.enc").st_size == 0:
        display_message("info", message="No passwords stored yet.")
        display_message("wait")
        return

    found = False
    with open("passwords.enc", "rb") as file:
        for line in file:
            encrypted_data = line.strip()
            if not encrypted_data:
                continue
            try:
                decrypted_data = cipher.decrypt(encrypted_data).decode().strip()
                parts = decrypted_data.split(",", 2)

                if len(parts) != 3:
                    display_message("warning", message=f"⚠️ Skipping invalid entry format: {repr(decrypted_data)}")
                    continue

                service, username, password = parts

                if service.lower() == service_name.lower():
                    display_message("info", message=f"🔐 Service: {service}, Username: {username}, Password: {password}")
                    found = True
            except Exception as e:
                display_message("warning", message=f"⚠️ Error decrypting entry during search: {e}")
                continue

    if not found:
        display_message("info", message=f"No password found for service: '{service_name}'")
    display_message("wait")


def delete_passwords():
    """Deletes all stored passwords after user confirmation."""
    display_message("warning", message="Are you sure you want to delete ALL passwords?")
    confirm = safe_ask(questionary.confirm, "Confirm deletion?", default=False)

    if confirm:
        if os.path.exists("passwords.enc"):
            os.remove("passwords.enc")
            display_message("success", message="✅ All passwords deleted.")
        else:
            display_message("info", message="No passwords file to delete.")
    elif confirm is False:
        display_message("info", message="Deletion cancelled.")
    display_message("wait")


def select_password_by_number():
    """Allows viewing, editing, or deleting a specific password entry by its number."""
    key = load_key()
    if key is None:
        return
    cipher = Fernet(key)

    if not os.path.exists("passwords.enc") or os.stat("passwords.enc").st_size == 0:
        display_message("info", message="No passwords stored yet.")
        display_message("wait")
        return

    with open("passwords.enc", "rb") as file:
        lines = file.readlines()

    if not lines:
        display_message("info", message="No passwords stored yet.")
        display_message("wait")
        return

    questionary.print("\n--- Current Passwords ---", style="bold")
    valid_entries = []
    for i, line in enumerate(lines):
        encrypted_data = line.strip()
        if not encrypted_data:
            continue
        try:
            decrypted_data = cipher.decrypt(encrypted_data).decode()
            service, username, password = decrypted_data.split(",", 2)
            valid_entries.append((i, service, username, password, line))
            questionary.print(f"{i + 1}. Service: {service}", style="fg:white")
        except Exception:
            pass

    if not valid_entries:
        display_message("info", message="No valid password entries found.")
        display_message("wait")
        return

    try:
        password_number_str = safe_ask(questionary.text, "🔢 Enter the password number to select:", style=custom_style)
        if password_number_str is None:
            display_message("info", message="Operation cancelled.")
            display_message("wait")
            return
        
        number = int(password_number_str)
        if not (1 <= number <= len(valid_entries)):
            display_message("error", message="Invalid number. Please enter a number from the list.")
            display_message("wait")
            return

        original_file_index, service, username, password, original_encrypted_line = valid_entries[number - 1]

    except ValueError:
        display_message("error", message="Invalid input. Please enter a number.")
        display_message("wait")
        return

    action = safe_ask(questionary.select,
        "What would you like to do with this entry?",
        choices=[
            "🔎 View details",
            "✏️ Edit entry",
            "🗑️ Delete entry",
            "❌ Cancel"
        ],
        style=custom_style
    )
    if action is None:
        display_message("info", message="Operation cancelled.")
        display_message("wait")
        return

    if action == "🔎 View details":
        display_message("info", message=f"🔐 Service: {service}, Username: {username}, Password: {password}")

    elif action == "✏️ Edit entry":
        new_service = safe_ask(questionary.text,
            " 🔧 Enter the new service name:",
            default=service,
            style=custom_style
        ) or service
        if new_service is None: return

        new_username = safe_ask(questionary.text,
            " 👤 Enter the new username:",
            default=username,
            style=custom_style
        ) or username
        if new_username is None: return

        new_password = safe_ask(questionary.password,
            " 🔑 Enter the new password (leave empty to keep current):",
            style=custom_style
        )
        new_password = new_password if new_password is not None and new_password.strip() != "" else password
        if new_password is None: return

        new_data = f"{new_service},{new_username},{new_password}".encode()
        lines[original_file_index] = cipher.encrypt(new_data) + b"\n"

        with open("passwords.enc", "wb") as file:
            file.writelines(lines)
        display_message("success", message="Entry updated successfully.")

    elif action == "🗑️ Delete entry":
        display_message("warning", message="Are you sure you want to delete this entry?")
        confirm_delete = safe_ask(questionary.confirm, "Confirm deletion?", default=False)
        if confirm_delete:
            del lines[original_file_index]
            with open("passwords.enc", "wb") as file:
                file.writelines(lines)
            display_message("success", message="🗑️ Entry deleted.")
        elif confirm_delete is False:
            display_message("info", message="Deletion cancelled.")

    elif action == "❌ Cancel":
        display_message("info", message="Operation cancelled.")

    display_message("wait")


def clear():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def main_menu():
    """Displays the main menu and returns the user's choice."""
    return questionary.select(
        "🔐 Password Manager — Choose an option:",
        choices=[
            "➕  Add a new password",
            "📂  View saved passwords",
            "🔍  Search for a password",
            "🗑️  Delete all passwords",
            "🔢  Select password by number",
            "❌  Exit"
        ],
        style=custom_style
    ).ask()


def main():
    """Main function to run the password manager application."""

    if not create_secure_key_file():
        sys.exit(0)

    if not confirm_master_password():
        sys.exit(0)

    while True:
        clear()
        print_banner()
        sys.stdout.write("\033[17H")
        sys.stdout.flush()

        choice = main_menu()

        if choice == "➕  Add a new password":
            save_password()

        elif choice == "📂  View saved passwords":
            view_passwords()

        elif choice == "🔍  Search for a password":
            search_password()

        elif choice == "🗑️  Delete all passwords":
            delete_passwords()
        elif choice == "🔢  Select password by number":
            select_password_by_number()

        elif choice == "❌  Exit":
            clear()
            display_message("success",message = f"Goodbye \n")
            # print("\nWINK say Goodbye ")
            break
        elif choice is None:
            handle_cancel()


if __name__ == "__main__":
    main()
