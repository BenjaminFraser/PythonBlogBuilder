from google.appengine.ext import ndb
import hashlib
import jinja2
import os
import random
import string
from string import letters
import webapp2

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

class Post(ndb.Model):
    subject = ndb.StringProperty(required = True)
    # text property, since it is unindexed and allows > 500 words
    content = ndb.TextProperty(required = True)
    # use auto_now_add = True to automatically create the created property
    created = ndb.DateTimeProperty(auto_now_add = True)
    creator = ndb.StringProperty(required = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)
    user_like_keys = ndb.StringProperty(repeated=True)
    comments = ndb.StringProperty(repeated=True)

    @classmethod
    def query_post(cls, ancestor_key):
        """Allows simple querying of posts for an individual User (ancestor)"""
        return cls.query(ancestor=ancestor_key).order(-cls.last_modified)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

    def render_shortened(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post_limited.html", p = self)


class User(ndb.Model):
    """User profile to store the details of each user registered.
    Attributes:
        name: The name of the user (str).
        email: The email address of the user (str).
    """
    username = ndb.StringProperty(required=True)
    pass_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty(required=True)
    liked_post_keys = ndb.StringProperty(repeated=True)
    disliked_post_keys = ndb.StringProperty(repeated=True)
    followed_user_keys = ndb.StringProperty(repeated=True)
    followers = ndb.IntegerProperty(default=0)

    @classmethod
    def new_user(cls, username, password, email):
        pass_hash = make_password_hash(username, password)
        return User(username=username, pass_hash=pass_hash, email=email)

    @classmethod 
    def fetch_by_id(cls, user_id):
        user = ndb.Key(User, int(user_id)).get()
        return user

    @classmethod
    def fetch_by_username(cls, username):
        user = User.query(User.username == username).get()
        return user

    def like_post(self, urlsafe_postkey, unlike=False):
        if not unlike:
            if urlsafe_postkey in self.liked_post_keys:
                return False
            else:
                self.liked_post_keys.append(str(urlsafe_postkey))
                self.put()
                return True
        else:
            if urlsafe_postkey in self.liked_post_keys:
                self.liked_post_keys.remove(str(urlsafe_postkey))
                self.put()
                return True
            else:
                return False

    def dislike_post(self, urlsafe_postkey, undislike=False):
        if urlsafe_postkey in self.disliked_post_keys:
            return False
        else:
            self.disliked_post_keys.append(str(urlsafe_postkey))
            self.put()
            return True

    def follow_user(self, urlsafe_userkey):
        if urlsafe_userkey in self.followed_user_keys:
            return False
        else:
            self.followed_user_keys.append(str(urlsafe_userkey))
            self.put()
            return True

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

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


#class Theme(ndb.Model):
#    layout_style = ndb.IntegerProperty()
#    background_image = ndb.PickleProperty()
#    text_colour = ndb.IntegerProperty()