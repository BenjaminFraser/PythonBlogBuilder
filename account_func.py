import hmac
import string
from string import letters
import random
import re
import hashlib

# Cookie securing functionality
SECRET = 'ddvtohCUzsOsd5RkZInx5ehUVpuzrZKvlrdXUdPk'

def make_hash_str(input_val):
    return hmac.new(SECRET, input_val).hexdigest()

def make_secure_val(input_val):
    # use "|" rather than ",", since GAE does not support "," within its cookies.
    return "{0}|{1}".format(str(input_val), make_hash_str(input_val))

def verify_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if str(make_secure_val(val)) == str(secure_val):
        return val

# User account functionality
def make_salt(length=5):
    """Creates a random salt value of length 5 by default. If an integer is given as an arg,
        a salt of the corresponding length will be generated and returned.
    Args:
        length (int): The length of the desired salt value, 5 by default.
    Returns:
        The generated salt value, as a string.
    """
    return ''.join(random.choice(string.letters+string.digits) for x in range(length))

def make_password_hash(name, password, salt=None):
    """Creates a secure password hash given a User name and password given as string arguments.
        A custom salt can be used through using the 'salt' keyword variable, equal to desired salt.
    Args:
        name (str): The User username, as a string.
        password (str): the User password, as a string.
        salt (str): The desired salt to be used within the password hash. None by default, in which case
                    a random salt of length 5 is used.
    Returns:
        The secure hash, in the form of a string, like so: "hash_value, salt_value"
    """
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(str(name) + str(password) + salt).hexdigest()
    return "{0},{1}".format(h, salt)

def valid_user_password(name, password, hash_val):
    """Takes a Users name, password and database hash_val and verifies that the user login
        details were valid.
    Args:
        name (str): The username of the User, as a string.
        password (str): The password entered by the user, as a string.
        hash_val (str): The hash value from the Datastore, as a string.
    Returns:
        True if the password and username credentials are valid, else returns False.
    """
    salt = hash_val.split(",")[1]
    return True if make_password_hash(name, password, salt) == hash_val else False


# User account creation validation functions, using regular expression.
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)