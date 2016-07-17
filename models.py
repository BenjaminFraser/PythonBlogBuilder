from google.appengine.ext import ndb
import hashlib
import jinja2
import os
import random
import string
import webapp2

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


class Post(ndb.Model):
    """Post entity to store the details of each post created.
    Attributes:
        subject: The subject of the post (str).
        content: The main text of the post (str).
        created: the date-time at which the post was created.
        creator: The username corresponding to the creator of the post.
        last_modified: The datetime at which the post was last modified.
        user_like_keys: A list of strings corresponding to User's that have liked. 
        user_dislike_keys: A list of strings corresponding to User's that have disliked.
        comments: pickleproperty for comments in the form of a list of 
                  tuples: [(user_urlsafekey, comment), ...]
    """
    subject = ndb.StringProperty(required=True)
    # text property, since it is unindexed and allows > 500 words
    content = ndb.TextProperty(required=True)
    # use auto_now_add = True to automatically create the created property
    created = ndb.DateTimeProperty(auto_now_add=True)
    creator = ndb.StringProperty(required=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    user_like_keys = ndb.StringProperty(repeated=True)
    user_dislike_keys = ndb.StringProperty(repeated=True)
    # pickleproperty for comments in the form of a list of tuples: [(user_urlsafekey, comment), ...]
    comments = ndb.PickleProperty(repeated=True)

    @classmethod
    def query_post(cls, ancestor_key):
        """Allows simple querying of posts for an individual User (ancestor)
        Args:
            ancestor_key (str): The user_key associated during post creation.
        """
        return cls.query(ancestor=ancestor_key).order(-cls.last_modified)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    def render_shortened(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post_limited.html", p=self)

    def delete_comment(self, comment_num, username):
        """Takes a given comment number (int) and username, and deletes the 
            relevant comment, providing the username matches the comment user.
        Args:
            comment_num (int): The row number of the comment to be deleted, as an int.
            username (str): The User's username, as a string.
        Returns:
            True if comment is deleted, or False if the comment is not found.
        """
        if username == self.comments[comment_num][0]:
            del self.comments[comment_num]
            return True
        else:
            return False

    def process_like(self, user_object, like_status):
        """Takes a given user_object entity and either adds or removes a user_key
            to the user_like_keys or user_dislike_keys dependent on given like_status.

        Args:
            user_object: An ndb.class User entity object for the selected user.
            like_status: A boolean variable to indicate the like status:
        """
        if like_status == 'like':
            if user_object.key.id() in self.user_like_keys:
                return False
            else:
                # add userkey to liked_user_keys and return True.
                self.user_like_keys.append(user_object.key.urlsafe())
                self.put()
                return True
        elif like_status == 'unlike':
            if user_object.key.id() in self.user_like_keys:
                self.user_like_keys.remove(str(user_object.key.urlsafe()))
                return True
            else:
                return False
        elif like_status == 'dislike':
            if user_object.key.id() in self.user_dislike_keys:
                return False
            else:
                # add userkey to disliked_user_keys and return True.
                self.user_dislike_keys.append(user_object.key.urlsafe())
                self.put()
                return True
        elif like_status == 'undislike':
            if user_object.key.id() in self.user_dislike_keys:
                self.user_dislike_keys.remove(str(user_object.key.urlsafe()))
                return True
            else:
                return False
        else:
            return False


class User(ndb.Model):
    """User profile to store the details of each user registered.
    Attributes:
        name: The name of the user (str).
        email: The email address of the user (str).
        pass_hash: The securely stored hash of a user's password (str).
        liked_post_keys: A list of strings corresponding to Post's the user 
                        has liked.
        disliked_post_keys: A list of strings corresponding to Post's the user 
                        has disliked.
        followed_user_keys: A list of key strings, corresponding to followed users.
        followers: The number of users who follow the user (int).
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
        """Takes a given urlsafe_postkey and places it into the User's liked_post_keys
            property. If already liked, returns False, else returns True.
        Args:
            urlsafe_postkey (str): The requested post, as a urlsafe string.
            unlike (bool): Keyword value, False if like chosen (default), True if unlike.
        """
        if not unlike:
            # check if postkey is already in liked list, if so return False
            if urlsafe_postkey in self.liked_post_keys:
                return False
            else:
                # check to see if user has disliked post, remove dislike if so
                if urlsafe_postkey in self.disliked_post_keys:
                    self.dislike_post(urlsafe_postkey, undislike=True)
                # add postkey to liked_post_keys and return True.
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
        """Takes a given urlsafe_postkey and places it into the User's disliked_post_keys
            property. If already disliked, returns False, else returns True.
        Args:
            urlsafe_postkey (str): The requested post, as a urlsafe string.
            undislike (bool): Keyword value, False if dislike chosen (default), True if undislike.
        """
        if not undislike:
            if urlsafe_postkey in self.disliked_post_keys:
                return False
            else:
                # check to see if user has liked post, remove like if so
                if urlsafe_postkey in self.liked_post_keys:
                    self.like_post(urlsafe_postkey, unlike=True)
                # add postkey to disliked_post_keys and return True
                self.disliked_post_keys.append(str(urlsafe_postkey))
                self.put()
                return True
        else:
            if urlsafe_postkey in self.disliked_post_keys:
                self.disliked_post_keys.remove(str(urlsafe_postkey))
                self.put()
                return True
            else:
                return False

    def follow_user(self, urlsafe_userkey, unfollow=False):
        """Takes a given urlsafe_userkey and places it into the User's followed_user_keys
            property. If already followed, returns False, else returns True. 
        Args:
            urlsafe_userkey (str): The requested user, as a urlsafe string.
            unfollow (bool): Keyword value, False if follow chosen (default), True if unfollow.
        """
        if not unfollow:
            if str(urlsafe_userkey) in self.followed_user_keys:
                return False
            else:
                self.followed_user_keys.append(str(urlsafe_userkey))
                self.put()
                return True
        else:
            if str(urlsafe_userkey) in self.followed_user_keys:
                self.followed_user_keys.remove(str(urlsafe_userkey))
                return True
            else:
                return False

    def is_liked_post(self, urlsafe_postkey, dislike=False):
        """Takes a given urlsafe postkey and checks if the post key is within the users
            liked/disliked_post_keys property, dependent on dislike keyword argument.
        Args:
            urlsafe_postkey (str): The corresponding post key, as a urlsafe str. 
            dislike (boolean): Checks for liked post if true, and disliked if false,
                                True by default. 
        """
        if dislike:
            if str(urlsafe_postkey) in self.disliked_post_keys:
                return True
            else:
                return False
        else:
            if str(urlsafe_postkey) in self.liked_post_keys:
                return True
            else:
                return False

    def is_followed_user(self, urlsafe_userkey):
        """Takes a given urlsafe userkey and checks whether or not the current user
            has the given userkey within its liked_post_keys property.
        Args:
            urlsafe_userkey (str): The corresponding post key, as a urlsafe str.
        """
        if str(urlsafe_userkey) in self.followed_user_keys:
            return True
        else:
            return False


# User account functionality
def make_salt(length=5):
    """Creates a random salt value of length 5 by default. If an integer is given as an arg,
        a salt of the corresponding length will be generated and returned.
    Args:
        length (int): The length of the desired salt value, 5 by default.
    Returns:
        The generated salt value, as a string.
    """
    return ''.join(random.choice(string.letters + string.digits) for x in range(length))


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

    # class Theme(ndb.Model):
    #    layout_style = ndb.IntegerProperty()
    #    background_image = ndb.PickleProperty()
    #    text_colour = ndb.IntegerProperty()
